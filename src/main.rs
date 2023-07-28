use std::{thread, collections::HashMap, time::Duration};
use async_std::task;
//use std::sync::mpsc;
use futures::channel::*;
use clap::Parser;
use serde_json::json;

mod network;
mod evaluator;
mod address_book;
mod common;
mod utils;

use address_book::*;
use evaluator::*;
use common::*;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    id: String,

    /// Fixed value to generate deterministic peer id
    #[clap(long)]
    seed: u8,
}

fn parse_addr_book_from_json() -> Pok3rAddrBook {
    let config = json!({
        "addr_book": [ //addr_book is a list of ed25519 pubkeys
            "12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X", //pubkey of node with seed 1
            "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3", //pubkey of node with seed 2
            "12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo"  //pubkey of node with seed 3
        ]
    });
    let mut peers: Vec<String> = config["addr_book"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| String::from(o.as_str().unwrap()))
        .collect();
    peers.sort();

    let mut output: Pok3rAddrBook = HashMap::new();
    let mut counter = 0;
    for peer in peers {
        let pok3rpeer = Pok3rPeer {
            peer_id: peer.to_owned(),
            node_id: counter,
        };

        output.insert(peer, pok3rpeer);
        counter += 1;
    }
    output
}

#[async_std::main]
async fn main() {
    let args = Args::parse();

    //these channels will connect the evaluator and the network daemons
    let (mut n2e_tx, n2e_rx) = mpsc::unbounded::<EvalNetMsg>();
    let (e2n_tx, e2n_rx) = mpsc::unbounded::<EvalNetMsg>();

    let netd_handle = thread::spawn(move || {
        let result = task::block_on(
            network::run_networking_daemon(
                args.seed, 
                &parse_addr_book_from_json(), 
                &mut n2e_tx,
                e2n_rx)
        );
        if let Err(err) = result {
            eprint!("Networking error {:?}", err);
        }
    });
    
    let addr_book = parse_addr_book_from_json();
    let mut evaluator = Evaluator::new(&args.id, addr_book, e2n_tx, n2e_rx).await;

    //this is a hack until we figure out
    task::block_on(async {
        task::sleep(Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    evaluator.test_networking().await;

    println!("-------------- Ready to compute -----------------");

    println!("testing beaver triples...");
    let (h_a, h_b, h_c) = evaluator.beaver(0).await;
    let a = evaluator.output_wire(&h_a).await;
    let b = evaluator.output_wire(&h_b).await;
    let c = evaluator.output_wire(&h_c).await;
    assert_eq!(c, a * b);

    println!("testing adder...");
    let h_r1 = evaluator.ran(1);
    let h_r2 = evaluator.ran(2);
    let r1 = evaluator.output_wire(&h_r1).await;
    let r2 = evaluator.output_wire(&h_r2).await;
    let h_sum_r1_r2 = evaluator.add(&h_r1, &h_r2);
    let sum_r1_r2 = evaluator.output_wire(&h_sum_r1_r2).await;
    assert_eq!(sum_r1_r2, r1 + r2);

    println!("testing multiplier...");
    let h_mult_r1_r2 = evaluator.mult(&h_r1, &h_r2, (&h_a, &h_b, &h_c)).await;
    let mult_r1_r2 = evaluator.output_wire(&h_mult_r1_r2).await;
    assert_eq!(mult_r1_r2, r1 * r2);

    println!("testing inverter...");
    let h_r1_inverted = evaluator.inv(&h_r1, &h_r2, (&h_a, &h_b, &h_c)).await;
    let r1_inverted = evaluator.output_wire(&h_r1_inverted).await;
    assert_eq!(r1_inverted, r1 * r1_inverted);

    println!("-------------- End compute -----------------");

    //eval_handle.join().unwrap();
    netd_handle.join().unwrap();
}