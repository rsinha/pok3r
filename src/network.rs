use futures::{future::Either, prelude::*, select, channel::*};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::OrTransport, upgrade},
    gossipsub, identity, mdns, noise,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Transport,
};
use libp2p_quic as quic;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::address_book::*;
use crate::common::*;

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::async_io::Behaviour,
}

fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;

    identity::Keypair::ed25519_from_bytes(bytes).expect("only errors on wrong length")
}

pub async fn run_networking_daemon(
    secret_key_seed: u8,
    addr_book: &Pok3rAddrBook,
    tx: &mut mpsc::UnboundedSender<EvalNetMsg>, 
    mut rx: mpsc::UnboundedReceiver<EvalNetMsg>) -> Result<(), Box<dyn Error>> {
    // Create a random PeerId
    //let id_keys = identity::Keypair::generate_ed25519();
    let id_keys: identity::Keypair = generate_ed25519(secret_key_seed);
    let local_peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {local_peer_id}");

    // Set up an encrypted DNS-enabled TCP Transport over the yamux protocol.
    let tcp_transport = tcp::async_io::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(&id_keys).expect("signing libp2p-noise static keypair"))
        .multiplex(yamux::Config::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();
    let quic_transport = quic::async_std::Transport::new(quic::Config::new(&id_keys));
    let transport = OrTransport::new(quic_transport, tcp_transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
        .build()
        .expect("Valid config");

    // build a gossipsub network behaviour
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(id_keys),
        gossipsub_config,
    )
    .expect("Correct configuration");
    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("mpc-test-net");
    // subscribes to our topic
    gossipsub.subscribe(&topic)?;

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let mdns = mdns::async_io::Behaviour::new(mdns::Config::default(), local_peer_id)?;
        let behaviour = MyBehaviour { gossipsub, mdns };
        SwarmBuilder::with_async_std_executor(transport, behaviour, local_peer_id).build()
    };

    // Read full lines from stdin
    //let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    //swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut connected_peers: Vec<PeerId> = vec![];
    let mut connection_informed: bool = false;
    // Kick it off
    loop {
        select! {
            //receives requests for publishing messages from the evaluator
            msg_to_send = rx.select_next_some() => {
                // let s = match msg_to_send {
                //     EvalNetMsg::Greeting(m) => serde_json::to_string(&m).unwrap(),
                //     EvalNetMsg::PublishShare(m) => serde_json::to_string(&m).unwrap(),
                //     EvalNetMsg::SendShare(m) => serde_json::to_string(&m).unwrap(),
                //     _ => panic!("Unexpected message received by networkd"),
                // };
                let s = serde_json::to_string(&msg_to_send).unwrap();
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(topic.clone(), <String as AsRef<[u8]>>::as_ref(&s)) {
                    println!("Publish error: {e:?}");
                }
            },
            //discovers peers, and notifies evaluator when all peers in addr_book are connected
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        let peer_id_encoded = peer_id.to_base58();
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        
                        if addr_book.contains_key(&peer_id_encoded) { 
                            connected_peers.push(peer_id.clone());

                            if !connection_informed && 
                                (connected_peers.len() == addr_book.len() - 1) {
                                let _r = tx.send(
                                    EvalNetMsg::ConnectionEstablished { success: true }
                                ).await;
                                // if let Err(err) = r {
                                //     eprint!("network error {:?}", err);
                                // }
                                connection_informed = true;
                            }
                        }
                    }
                },
                //handle peers that have dropped off unexpectedly
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                //all received messages over gossip channel are pushed to the evaluator
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: _peer_id,
                    message_id: _id,
                    message,
                })) => { 
                    let msg_as_str = String::from_utf8_lossy(&message.data);
                    println!("networking: about to serde {}", msg_as_str);
                    let deserialized_struct = serde_json::from_str(&msg_as_str).unwrap();
                    //println!("networking: parsed as json {:?}", deserialized_struct);
                    let r = tx.send(deserialized_struct).await;
                    if let Err(err) = r {
                        eprint!("network error {:?}", err);
                    }
                },
                //prints out the address this program is listening on for new connections
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}