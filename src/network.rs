use futures::{future::Either, prelude::*, select, channel::*};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::OrTransport, upgrade},
    gossipsub, identity, mdns, noise,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Transport,
};
use libp2p_quic as quic;
use std::collections::{hash_map::DefaultHasher, HashMap};
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
                    let deserialized_struct = serde_json::from_str(&msg_as_str).unwrap();
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

pub struct MessagingSystem {
    /// local peer id
    pub id: Pok3rPeerId,
    /// information about all other peers
    pub addr_book: Pok3rAddrBook,
    /// receiver channel from the networkd
    rx: mpsc::UnboundedReceiver<EvalNetMsg>,
    /// sender channel towards the networkd
    tx: mpsc::UnboundedSender<EvalNetMsg>,
    /// stores incoming messages indexed by identifier and then by peer id
    mailbox: HashMap<String, HashMap<String, String>>,
}

impl MessagingSystem {
    pub async fn new(
        id: &Pok3rPeerId,
        addr_book: Pok3rAddrBook,
        tx: mpsc::UnboundedSender<EvalNetMsg>,
        mut rx: mpsc::UnboundedReceiver<EvalNetMsg>
    ) -> Self {
        // we expect the first message from the
        // networkd to be a connection established;
        // so, here we will loop till we get that
        loop {
            //do a blocking recv on the rx channel
            let msg: EvalNetMsg = rx.select_next_some().await;
            match msg {
                EvalNetMsg::ConnectionEstablished { success } => {
                    if success {
                        println!("evaluator connected to the network");
                        break;
                    }
                },
                _ => continue,
            }
        }

        MessagingSystem {
            id: id.clone(),
            addr_book,
            rx,
            tx,
            mailbox : HashMap::new()
        }
    }

    pub fn get_my_id(&self) -> u64 {
        get_node_id_via_peer_id(&self.addr_book, &self.id).unwrap()
    }

    pub async fn send_to_all(
        &mut self,
        handles: impl AsRef<[String]>,
        values: impl AsRef<[String]>,
    ) {
        assert!(handles.as_ref().len() == values.as_ref().len() && handles.as_ref().len() > 0);

        let msg = if handles.as_ref().len() > 1 {
            EvalNetMsg::PublishBatchValue {
                sender: self.id.clone(),
                handles: handles.as_ref().to_owned(),
                values: values.as_ref().to_owned()
            }
        } else {
            EvalNetMsg::PublishValue {
                sender: self.id.clone(),
                handle: handles.as_ref()[0].clone(),
                value: values.as_ref()[0].clone()
            }
        };
        let r = self.tx.send(msg).await;
        if let Err(err) = r {
            eprint!("evaluator error {:?}", err);
        }
    }

    pub async fn recv_from_all(
        &mut self,
        identifier: &String
    ) -> Vec<String> {
        let mut messages = vec![];
        let peers: Vec<Pok3rPeerId> = self.addr_book.keys().cloned().collect();
        for peer_id in peers {
            if self.id.eq(&peer_id) { continue; }

            loop { //loop over all incoming messages till we find msg from peer
                if self.mailbox.contains_key(identifier) {
                    let sender_exists_for_handle = self.mailbox
                        .get(identifier)
                        .unwrap()
                        .contains_key(&peer_id);
                     //if we already have it, break out!
                    if sender_exists_for_handle { break; }
                }

                let msg: EvalNetMsg = self.rx.select_next_some().await;
                self.process_next_message(&msg);
            }

            // if we got here, we can assume we have the message from peer_id
            let msg = self.mailbox
                .get(identifier)
                .unwrap()
                .get(&peer_id)
                .unwrap()
                .clone();

            messages.push(msg);
        }

        //clear the mailbox because we might want to use identifier again
        self.mailbox.remove(identifier);

        messages
    }

    //returns the handle which 
    fn process_next_message(&mut self, msg: &EvalNetMsg) {
        match msg {
            EvalNetMsg::PublishValue {
                sender,
                handle,
                value
            } => {
                self.accept_handle_and_value_from_sender(sender, handle, value);
            },
            EvalNetMsg::PublishBatchValue {
                sender,
                handles,
                values
            } => {
                assert_eq!(handles.len(), values.len());

                for (h,v) in handles.iter().zip(values.iter()) {
                    self.accept_handle_and_value_from_sender(sender, h, v);
                }
            },
            _ => return,
        }
    }

    fn accept_handle_and_value_from_sender(&mut self,
        sender: &String,
        handle: &String,
        value: &String
    ) {
        // if already exists, then ignore
        if self.mailbox.contains_key(handle) {
            let sender_exists_for_handle = self.mailbox
                .get(handle)
                .unwrap()
                .contains_key(sender);
            if sender_exists_for_handle { return; } //ignore duplicate msg!
        } else {
            //mailbox never got a message by this handle so lets make room for it
            self.mailbox.insert(handle.clone(), HashMap::new());
        }

        self.mailbox
            .get_mut(handle)
            .unwrap()
            .insert(sender.clone(), value.clone());
    }
}