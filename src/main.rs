use std::{thread, collections::{HashMap, HashSet}, time::Duration};
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
mod kzg;

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
    let mut mpc = Evaluator::new(&args.id, addr_book, e2n_tx, n2e_rx).await;

    //this is a hack until we figure out
    task::block_on(async {
        task::sleep(Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    mpc.test_networking().await;
    evaluator::perform_sanity_testing(&mut mpc).await;
    shuffle_deck(&mut mpc).await;

    //eval_handle.join().unwrap();
    netd_handle.join().unwrap();
}

fn map_roots_of_unity_to_cards() -> HashMap<F, String> {
    let mut output: HashMap<F, String> = HashMap::new();
    
    // get generator for the 64 powers of 64-th root of unity
    let ω = utils::multiplicative_subgroup_of_size(64);

    // map each power to a card
    // map 52 real cards
    for i in 0..52 {
        let ω_pow_i = utils::compute_power(&ω, i as u64);
        let card_name = i.to_string();
        output.insert(ω_pow_i, card_name);
    }

    //and 12 jokers
    for i in 52..64 {
        let ω_pow_i = utils::compute_power(&ω, i as u64);
        output.insert(ω_pow_i, String::from("Joker"));
    }

    output
}

async fn shuffle_deck(evaluator: &mut Evaluator) {
    println!("-------------- Starting Pok3r shuffle -----------------");

    //step 1: parties invoke F_RAN to obtain [sk]
    let sk = evaluator.ran();

    //stores (handle, wire value) pairs
    let mut cards = Vec::new();
    //stores set of card prfs encountered
    let mut prfs = HashSet::new();

    while cards.len() < 64 { //until you get 64 unique cards
        let h_r = evaluator.ran();
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        let a_i = evaluator.ran();
        let c_i = evaluator.ran_64(&a_i).await;
        let t_i = evaluator.add(&c_i, &sk);
        let t_i = evaluator.inv(
            &t_i,
            &h_r,
            (&h_a, &h_b, &h_c)
        ).await;

        // y_i = g^{1 / (sk + w_i)}
        let y_i = evaluator.output_wire_in_exponent(&t_i).await;

        //add card if it hasnt been seen before
        if ! prfs.contains(&y_i) {
            prfs.insert(y_i.clone());
            cards.push((c_i.clone(), evaluator.get_wire(&c_i)));
        }
    }

    let card_mapping = map_roots_of_unity_to_cards();
    for (h_c, _card_share) in cards {
        let opened_card = evaluator.output_wire(&h_c).await;
        println!("{}", card_mapping.get(&opened_card).unwrap());
    }

    println!("-------------- Ending Pok3r shuffle -----------------");

}


async fn _compute_permutation_argument(
    evaluator: &mut Evaluator,
    card_shares: &Vec<F>
) {
    let mut r_is = vec![]; //vector of (handle, share_value) pairs
    let mut r_inv_is = vec![]; //vector of (handle, share_value) pairs

    for _i in 0..53 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;
        let h_t = evaluator.ran();

        let h_r_i = evaluator.ran();
        let h_r_inv_i = evaluator.inv(
            &h_r_i,
            &h_t,
            (&h_a, &h_b, &h_c)
        ).await;

        r_is.push((h_r_i.clone(), evaluator.get_wire(&h_r_i)));
        r_inv_is.push((h_r_inv_i.clone(), evaluator.get_wire(&h_r_inv_i)));
    }

    let mut b_is = vec![]; //vector of (handle, share_value) pairs
    for i in 0..52 {
        let (h_a, h_b, h_c) = evaluator.beaver().await;

        let h_r_inv_0 = &r_inv_is.get(0).unwrap().0;
        let h_r_i_plus_1 = &r_is.get(i+1).unwrap().0;

        let h_b_i = evaluator.mult(
            h_r_inv_0,
            h_r_i_plus_1,
            (&h_a, &h_b, &h_c)
        ).await;

        b_is.push((h_b_i.clone(), evaluator.get_wire(&h_b_i)));
    }

    let f_name = String::from("f");
    let f_share = utils::interpolate_poly_over_mult_subgroup(card_shares);
    let f_share_com = utils::commit_poly(&f_share);
    let f_com = evaluator.add_group_elements_from_all_parties(&f_share_com, &f_name).await;

    let ω = utils::multiplicative_subgroup_of_size(64);
    let v_evals: Vec<F> = (0..52)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect();
    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    let v_com = utils::commit_poly(&v);

    //let γ1 = fiat_shamir_hash(f_com, v_com);



}

