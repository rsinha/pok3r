use std::{thread, collections::{HashMap, HashSet}, time::{Duration, Instant}, vec, ops::*};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::Field;
use ark_poly::{ GeneralEvaluationDomain, EvaluationDomain, Polynomial, univariate::{DensePolynomial, DenseOrSparsePolynomial}, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{Zero, One, UniformRand};
use async_std::task;
use futures::channel::*;
use clap::Parser;
use kzg::{UniversalParams, KZG10};
use num_bigint::BigUint;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;

mod network;
mod evaluator;
mod address_book;
mod common;
mod utils;
mod kzg;
mod encoding;

use address_book::*;
use evaluator::*;
use common::*;

pub const PERFORM_TESTING: bool = false;

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

    /// number of parties doing the mpc
    #[clap(long)]
    parties: u64,
}

/*
Seed 1 peer id: 12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X
Seed 2 peer id: 12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3
Seed 3 peer id: 12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo
Seed 4 peer id: 12D3KooWLJtG8fd2hkQzTn96MrLvThmnNQjTUFZwGEsLRz5EmSzc
Seed 5 peer id: 12D3KooWSHj3RRbBjD15g6wekV8y3mm57Pobmps2g2WJm6F67Lay
Seed 6 peer id: 12D3KooWDMCQbZZvLgHiHntG1KwcHoqHPAxL37KvhgibWqFtpqUY
Seed 7 peer id: 12D3KooWLnZUpcaBwbz9uD1XsyyHnbXUrJRmxnsMiRnuCmvPix67
Seed 8 peer id: 12D3KooWQ8vrERR8bnPByEjjtqV6hTWehaf8TmK7qR1cUsyrPpfZ
Seed 9 peer id: 12D3KooWNRk8VBuTJTYyTbnJC7Nj2UN5jij4dJMo8wtSGT2hRzRP
Seed 10 peer id: 12D3KooWFHNBwTxUgeHRcD3g4ieiXBmZGVyp6TKGWRKKEqYgCC1C
Seed 11 peer id: 12D3KooWHbEputWi1fJAxoYgmvvDe3yP7acTACqmXKGYwMgN2daQ
Seed 12 peer id: 12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ
Seed 13 peer id: 12D3KooWFNisMCMFB4sxKjQ4VLoTrMYh7fUJqXr1FMwhqAwfdxPS
Seed 14 peer id: 12D3KooW9ubkfzRCQrUvcgvSqL2Cpri5pPV9DuyoHptvshVcNE9h
Seed 15 peer id: 12D3KooWRVJCFqFBrasjtcGHnRuuut9fQLsfcUNLfWFFqjMm2p4n
Seed 16 peer id: 12D3KooWGtVQAq3A8GPyq5ZuwBoE4V278EkDpETijz1dm7cY4LsG
Seed 17 peer id: 12D3KooWGjxVp88DuWx6P6cN5ZLtud51TNWK6a7K1h9cYb8qDuci
Seed 18 peer id: 12D3KooWDWC9G1REgGwHTzVNtXL8x6okkRQzsYb7V9mw9UGKhC1H
Seed 19 peer id: 12D3KooWE92WS4t4UBFxryqsx78hSaFaZMLaAkRwkynjsL1mdt8h
Seed 20 peer id: 12D3KooWPcbijTPjNkihfs3DcJiMb1iQC1B2BCzP3vSggGvUgZsC
Seed 21 peer id: 12D3KooWE1hRi1pECQ6bfxmeybMFEtYcTjJuhjxc75dZZLXwrdwy
Seed 22 peer id: 12D3KooWCxkD42pVy9VZXGPQgBmL2ekc9kxME5YwriN3xTN6aBMx
Seed 23 peer id: 12D3KooWFYZ24pnTgzhPJmznbMQTv8g9xdJANuM8wjkbCGrhWDvP
Seed 24 peer id: 12D3KooWSM6emJRiK1AzUG39eFW42k8AUKLCk3fTFLh7GU1hPMFs
Seed 25 peer id: 12D3KooWM7du63Ft3U51pDpJqNyiGRVU3Us2f4iuiwUEyxsB5P2M
Seed 26 peer id: 12D3KooWCTvrtiEPSzY2UixVRuxVc81TGZjYHGU8YkJ7wuBrRRU8
Seed 27 peer id: 12D3KooWNLMpwyVysPSUj93RqpTDMxv5V9AsXc7NPgZPRUg4qD28
Seed 28 peer id: 12D3KooWJQK2dHWVMKPm9e1RPYgtQeix1hmS84B87rzhCP3uBep1
Seed 29 peer id: 12D3KooWP37FF5aY62MjcP5UJr1e3KJyu9cuARGFnFnTEkVdz6eh
Seed 30 peer id: 12D3KooWNjR7M1659fBQXPpEs9tj959tgpD5T118vLojZKci9d4x
Seed 31 peer id: 12D3KooWLcqHxG25dqsQqZAPz2zofcLrDga83pzsKAxy1G7GVbzg
Seed 32 peer id: 12D3KooWDrAvsiX8hM5yVpDMrPEwSFRfQguLdBCVKgsYbVnqk2P4
Seed 33 peer id: 12D3KooWPEF7YrJx5bNKRr57s45UmEBV4pzpND2bpZDVZLzxsYLi
Seed 34 peer id: 12D3KooWMAXwrRcBdK3hFECY7b69PVW5rfHRa2WQPmbmMezZnEVG
Seed 35 peer id: 12D3KooWPMogJdb3k6PsLyaKwUXLmQJ2GBFTo656pSpGjAjHcfp9
Seed 36 peer id: 12D3KooWG7n1i8ZaMpj8d4UanqU6bnccmxkG1xgXsZWUE9191MZS
Seed 37 peer id: 12D3KooWKVWTrj63w9fYjPB8g5tGMyXDzaYJXX57gBMpWSc6rJiw
Seed 38 peer id: 12D3KooWHnBg5VSrypsNtoct6DGmd5CWg9ihxo9hxHXzxUYru3rw
Seed 39 peer id: 12D3KooWNzjpBvGcuFM3mGmDigzoyACZunz9qNieTbZaMWaC31uY
Seed 40 peer id: 12D3KooWQQmeaydZewRjdG1GUo8wrVSm6N9oigxjh769pPtGT3rp
Seed 41 peer id: 12D3KooWSahP5pFRCEfaziPEba7urXGeif6T1y8jmodzdFUvzBHj
Seed 42 peer id: 12D3KooWR2KSRQWyanR1dPvnZkXt296xgf3FFn8135szya3zYYwY
Seed 43 peer id: 12D3KooWBgJMyM6Akfx5hZcaa3F6zXVCpQykNXGqs96pDi4L71DR
Seed 44 peer id: 12D3KooWSY3udBzEcr8m838kxdcAZESH4jAmTvdvMKGgPNiQyJwu
Seed 45 peer id: 12D3KooWRrGbJ2SCwvmhLi3ESnAuEehg5A1UXzsLSNF6auKYNcks
Seed 46 peer id: 12D3KooWCPq8audTqV5k7W76JuNNSdpvU3fsMs42PkJY5hz3mu5T
Seed 47 peer id: 12D3KooWEGy5nh4CaFhiqbgvF31XmKwTa54a8XtFJoNz7yEBaBrP
Seed 48 peer id: 12D3KooWA768LzHMatxkjD1f9DrYW375GZJr6MHPCNEdDtHeTNRt
Seed 49 peer id: 12D3KooWRhFCXBhmsMnur3up3vJsDoqWh4c39PKXgSWwzAzDHNLn
Seed 50 peer id: 12D3KooWFFehYddGiX86tLFYPQ7BvWxhz6jNq4zQTBKgAGjDhuD3
Seed 51 peer id: 12D3KooWJj8KtUk7ie25RzJWikPXrEXmkWWLcC7MrD27PZZcmChi
Seed 52 peer id: 12D3KooWL3Q1jWvi5NNQAayzx5LCQr8SbnhGGAR6FBbh3zedzzNb
Seed 53 peer id: 12D3KooWMi16FDcmYbWsZ3WpWsLozmyz1X32CRisZoo5HzfUQnPn
Seed 54 peer id: 12D3KooWFV5G2smxejwXkXrHh8jqbqkPWdTHAwjfanWpmfDQLoaa
Seed 55 peer id: 12D3KooWCM74tY32ueDPKwEoqzdgdgSttSXt4vNkcUqE7v1BRGPK
Seed 56 peer id: 12D3KooWD8ws6HaggH9viHgi7FuCm4MdbAehiALBSUdcojPbD2i9
Seed 57 peer id: 12D3KooWHj7FJaFfC7ppoN2dnbUN1rfJq7BvSBzGXns5c5uXAhDM
Seed 58 peer id: 12D3KooWR8Ve6aQQRRnvfP9XzAYBL1fCybKc2eMmbiKY4eY9Bhzf
Seed 59 peer id: 12D3KooWAoztSYrzkFDTt7gc4dEyHnEgFi5HNfdjwjWn198e159K
Seed 60 peer id: 12D3KooWGFtv2Za5hLSpdc5piWKqgDvHJnydRoctVHhf6NDuZUEs
Seed 61 peer id: 12D3KooWNn92KJu4UCdp7WnqDrWhhXzAz1qknXvJYNNVgoNJPJpV
Seed 62 peer id: 12D3KooWSK6f2ZJLRX8Q3LiuVnj9y3yXqJgFguJh7gdjtsSomnS8
Seed 63 peer id: 12D3KooWHV2zfje5uXRV5nPsqArHdrVrh7GaAJVyhwr8ffZZ16om
*/

fn parse_addr_book_from_json(num_parties: u64) -> Pok3rAddrBook {
    let config = json!({
        "addr_book": [ //addr_book is a list of ed25519 pubkeys
            "12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X",
            "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3",
            "12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
            "12D3KooWLJtG8fd2hkQzTn96MrLvThmnNQjTUFZwGEsLRz5EmSzc",
            "12D3KooWSHj3RRbBjD15g6wekV8y3mm57Pobmps2g2WJm6F67Lay",
            "12D3KooWDMCQbZZvLgHiHntG1KwcHoqHPAxL37KvhgibWqFtpqUY",
            "12D3KooWLnZUpcaBwbz9uD1XsyyHnbXUrJRmxnsMiRnuCmvPix67",
            "12D3KooWQ8vrERR8bnPByEjjtqV6hTWehaf8TmK7qR1cUsyrPpfZ",
            "12D3KooWNRk8VBuTJTYyTbnJC7Nj2UN5jij4dJMo8wtSGT2hRzRP",
            "12D3KooWFHNBwTxUgeHRcD3g4ieiXBmZGVyp6TKGWRKKEqYgCC1C",
            "12D3KooWHbEputWi1fJAxoYgmvvDe3yP7acTACqmXKGYwMgN2daQ",
            "12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ",
            "12D3KooWFNisMCMFB4sxKjQ4VLoTrMYh7fUJqXr1FMwhqAwfdxPS",
            "12D3KooW9ubkfzRCQrUvcgvSqL2Cpri5pPV9DuyoHptvshVcNE9h",
            "12D3KooWRVJCFqFBrasjtcGHnRuuut9fQLsfcUNLfWFFqjMm2p4n",
            "12D3KooWGtVQAq3A8GPyq5ZuwBoE4V278EkDpETijz1dm7cY4LsG",
            "12D3KooWGjxVp88DuWx6P6cN5ZLtud51TNWK6a7K1h9cYb8qDuci",
            "12D3KooWDWC9G1REgGwHTzVNtXL8x6okkRQzsYb7V9mw9UGKhC1H",
            "12D3KooWE92WS4t4UBFxryqsx78hSaFaZMLaAkRwkynjsL1mdt8h",
            "12D3KooWPcbijTPjNkihfs3DcJiMb1iQC1B2BCzP3vSggGvUgZsC",
            "12D3KooWE1hRi1pECQ6bfxmeybMFEtYcTjJuhjxc75dZZLXwrdwy",
            "12D3KooWCxkD42pVy9VZXGPQgBmL2ekc9kxME5YwriN3xTN6aBMx",
            "12D3KooWFYZ24pnTgzhPJmznbMQTv8g9xdJANuM8wjkbCGrhWDvP",
            "12D3KooWSM6emJRiK1AzUG39eFW42k8AUKLCk3fTFLh7GU1hPMFs",
            "12D3KooWM7du63Ft3U51pDpJqNyiGRVU3Us2f4iuiwUEyxsB5P2M",
            "12D3KooWCTvrtiEPSzY2UixVRuxVc81TGZjYHGU8YkJ7wuBrRRU8",
            "12D3KooWNLMpwyVysPSUj93RqpTDMxv5V9AsXc7NPgZPRUg4qD28",
            "12D3KooWJQK2dHWVMKPm9e1RPYgtQeix1hmS84B87rzhCP3uBep1",
            "12D3KooWP37FF5aY62MjcP5UJr1e3KJyu9cuARGFnFnTEkVdz6eh",
            "12D3KooWNjR7M1659fBQXPpEs9tj959tgpD5T118vLojZKci9d4x",
            "12D3KooWLcqHxG25dqsQqZAPz2zofcLrDga83pzsKAxy1G7GVbzg",
            "12D3KooWDrAvsiX8hM5yVpDMrPEwSFRfQguLdBCVKgsYbVnqk2P4",
        ]
    });
    let peers: Vec<String> = config["addr_book"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| String::from(o.as_str().unwrap()))
        .collect();

    let mut output: Pok3rAddrBook = HashMap::new();
    let mut counter = 0;
    for peer in &peers[0..num_parties as usize] {
        let pok3rpeer = Pok3rPeer {
            peer_id: peer.to_owned(),
            node_id: counter,
        };

        output.insert(peer.to_owned(), pok3rpeer);
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
                &parse_addr_book_from_json(args.parties), 
                &mut n2e_tx,
                e2n_rx)
        );
        if let Err(err) = result {
            eprint!("Networking error {:?}", err);
        }
    });
    
    let addr_book = parse_addr_book_from_json(args.parties);
    let mut mpc = Evaluator::new(&args.id, addr_book, e2n_tx, n2e_rx).await;

    //this is a hack until we figure out
    task::block_on(async {
        task::sleep(Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    // KZG setup runs once
    let pp = utils::setup_kzg(1024);

    // Actual protocol
    let (card_share_handles, card_shares) = shuffle_deck(&mut mpc).await;
    println!("Generated a deck of {} cards", card_share_handles.len());
    
    let (perm_proof, alpha1) = compute_permutation_argument(
        &pp, 
        &mut mpc, 
        card_share_handles.clone(), 
        &card_shares
    ).await;

    // Get a random public key pk in G2 - for testing (should be generated by DKG)
    // FIXME: Implement DKG to generate the public key
    let mut seeded_rng = StdRng::from_seed([42u8; 32]);
    let msk = F::rand(&mut seeded_rng);
    let pk = G2::generator().mul(msk);

    // Get random ids as byte strings
    let ids = (0..PERM_SIZE)
        .into_iter()
        .map(|i| BigUint::from(i as u8))
        .collect::<Vec<BigUint>>();

    // Encrypt and prove
    //let s_encrypt = Instant::now();
    let encrypt_proof = encrypt_and_prove(
        &pp, 
        &mut mpc, 
        card_share_handles.clone(), 
        perm_proof.f_com, 
        alpha1,
        pk, 
        ids.clone()
    ).await;

    // decrypt all cards
    let cache = compute_decryption_cache();
    let mut decrypted_cards = Vec::new();
    for i in 0..PERM_SIZE {
        let hash_id = G1::generator().mul(F::from(ids[i].clone()));
        let dec_key = hash_id * msk;

        if i >= (PERM_SIZE - DECK_SIZE) {
            let card = decrypt_one_card(i, &dec_key, &encrypt_proof, &cache).unwrap();
            decrypted_cards.push(card);
            print!("{},", card);
        }
    }

    // we can verify the proof, but let's also do a sanity check
    // check that decrypted cards is a permutation of 0..51
    let mut sorted_cards = decrypted_cards.clone();
    sorted_cards.sort_unstable();
    let expected_cards: Vec<usize> = (0..DECK_SIZE).collect();
    assert_eq!(sorted_cards, expected_cards, "Decrypted cards are not a valid permutation of 0..51");
    
    let verified = verify_permutation_argument(&pp, &perm_proof);
    assert!(verified, "Permutation argument verification failed");


    let verified = local_verify_encryption_proof(&pp, &encrypt_proof).await;
    assert!(verified, "Encryption proof verification failed");

    println!("completed.");

    netd_handle.join().unwrap();
}

fn compute_decryption_cache() -> Vec<Gt> {
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w_powers = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&w, i as u64))
        .collect::<Vec<F>>();

    let cache: Vec<Gt> = w_powers
        .iter()
        .map(|x| Gt::generator() * x)
        .collect();

    cache
}

async fn shuffle_deck(evaluator: &mut Evaluator) -> (Vec<String>, Vec<F>) {
    //step 1: parties invoke F_RAN to obtain [sk]
    let sk = evaluator.ran();

    //stores (handle, wire value) pairs
    let mut card_share_handles = Vec::new();
    let mut card_share_values = Vec::new();
    //stores set of card prfs encountered
    let mut prfs = HashSet::new();

    // Compute prfs for cards 52 to 63 and add to prfs first
    // So that the positions of these cards are fixed in the permutation

    let ω = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let powers_of_ω = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect::<Vec<F>>();

    // y_i = g^{1 / (sk + w_i)}
    let denoms = (DECK_SIZE..PERM_SIZE)
        .into_iter()
        .map(|i| evaluator.clear_add(&sk, powers_of_ω[i]))
        .collect::<Vec<String>>();

    let t_is = evaluator.batch_inv(&denoms).await;

    let y_is = evaluator.batch_output_wire_in_exponent(&t_is).await;

    // first include the cards 52..63 within the prf set and return set
    for i in 0..(PERM_SIZE - DECK_SIZE) {
        prfs.insert(y_is[i].clone());
        let handle = evaluator.fixed_wire_handle(powers_of_ω[i + DECK_SIZE]);
        card_share_handles.push(handle.clone());
        card_share_values.push(evaluator.get_wire(&handle));
    }

    // collect NUM_SAMPLES worth of random cards
    let c_is = evaluator.batch_ran_64(NUM_SAMPLES).await;

    let t_is = (0..NUM_SAMPLES)
        .into_iter()
        .map(|i| evaluator.add(&c_is[i], &sk))
        .collect::<Vec<String>>();

    let t_is = evaluator.batch_inv(&t_is).await;
    let y_is = evaluator.batch_output_wire_in_exponent(&t_is).await;

    for i in 0..NUM_SAMPLES {
        //add card if it hasnt been seen before
        if ! prfs.contains(&y_is[i]) {
            prfs.insert(y_is[i].clone());
            card_share_handles.push(c_is[i].clone());
            card_share_values.push(evaluator.get_wire(&c_is[i]));
        }
    }

    // Assert that the length is 64
    assert_eq!(card_share_handles.len(), PERM_SIZE, 
        "We don't have enough cards - try again");

    return (card_share_handles.clone(), card_share_values);
}

async fn compute_permutation_argument(
    pp: &UniversalParams<Curve>,
    evaluator: &mut Evaluator,
    card_share_handles: Vec<String>,
    card_share_values: &Vec<F>,
) -> (PermutationProof, String) {

    // Compute r_i and r_i^-1
    let r_is = (0..PERM_SIZE+1)
        .into_iter()
        .map(|_i| evaluator.ran())
        .collect::<Vec<String>>();

    let r_inv_is = evaluator.batch_inv(&r_is).await;

    // Compute b_i from r_i and r_i^-1; b_i = r_i / r_0 for i in 0..65
    let b_is = evaluator.batch_mult(
        &vec![r_inv_is[0].clone(); PERM_SIZE], 
        &r_is[1..PERM_SIZE+1].to_vec()
    ).await;

    // 8: Interpret the vector fi as evaluations of a polynomial f(X).
    let f_name = String::from("perm_f");
    let f_share = 
        utils::interpolate_poly_over_mult_subgroup(card_share_values);
    let f_share_com = KZG10::commit_g1(pp, &f_share);

    // Commit to hiding polynomials [alpha1,alpha2]*(x^PERM_SIZE - 1)
    let alpha1 = evaluator.ran();
    let alpha2 = evaluator.ran();
    
    let vanishing_poly = utils::compute_vanishing_poly(PERM_SIZE);
    let alpha1_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&alpha1));
    let alpha2_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&alpha2));

    // Commit to f(X) + alpha1 * (x^PERM_SIZE - 1)
    // Note that the polynomial itself isn't being changed, just the commitment.

    let hiding_f_com = f_share_com + alpha1_vanish_poly_share_com;
    let f_com = evaluator.add_g1_elements_from_all_parties(&hiding_f_com, &f_name).await;

    // 9: Define the degree-64 polynomial v(X) such that the evaluation vector is (1, ω, . . . , ω63)
    // This polynomial is the unpermuted vector of cards 
    let ω = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let v_evals: Vec<F> = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&ω, i as u64))
        .collect();
    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    
    // Commit to v(X) which is the public polynomial
    let v_com = KZG10::commit_g1(pp, &v);

    // 12: Parties locally compute γ1 = FSHash(C,V )
    // Hash v_com and f_com to obtain randomness for batching
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    f_com.serialize_uncompressed(&mut f_bytes).unwrap();

    let y1 = utils::fs_hash(vec![&v_bytes, &f_bytes], 1)[0];

    // 13: Locally compute g(X) shares from f(X) shares
    let mut g_eval_shares = vec![];
    let mut h_g_shares = vec![];
    for i in 0..PERM_SIZE {

        // Get a handle for g_i for later
        h_g_shares.push(evaluator.clear_add(&card_share_handles[i], y1));

        let g_share_i = evaluator.get_wire(&h_g_shares[i].clone());
        g_eval_shares.push(g_share_i);
    }

    let g_share_poly = 
        utils::interpolate_poly_over_mult_subgroup(&g_eval_shares.clone());

    // Commit to g(X) - the hiding variant derived from f(X): just add alpha1 * (x^PERM_SIZE - 1)
    let g_share_com = KZG10::commit_g1(pp, &g_share_poly);
    let hiding_g_com = g_share_com + alpha1_vanish_poly_share_com;
    let g_com = evaluator.add_g1_elements_from_all_parties(&hiding_g_com, &String::from("perm_g")).await;

    // 14: Compute h(X) = v(X) + y1
    let mut h_evals = vec![];
    for i in 0..PERM_SIZE {
        let h_i = v_evals[i] + y1;
        h_evals.push(h_i);
    }
    let h_poly = utils::interpolate_poly_over_mult_subgroup(&h_evals);

    // Compute s_i' and t_i'

    let h_h_inv_g_is = (0..PERM_SIZE)
        .into_iter()
        .map(|i| {
            let h_inv_i = h_evals[i].inverse().unwrap();
            let h_g_i = &h_g_shares[i];
            evaluator.scale(h_g_i, h_inv_i)
        })
        .collect::<Vec<String>>();

    let h_s_prime_is = evaluator.batch_mult(
        &r_is[0..PERM_SIZE].to_vec(), 
        &h_h_inv_g_is
    ).await;
    let h_t_prime_is = evaluator.batch_mult(
        &r_inv_is[1..PERM_SIZE+1].to_vec(), 
        &h_s_prime_is
    ).await;

    let t_prime_is = evaluator.batch_output_wire(&h_t_prime_is).await;

    // Locally compute t_i
    // 20: for i ← 0 . . . 63 do
    // 21: Parties locally compute [ti]p ← [bi]p · ∏ij=0 t′j
    // 22: end for
    let mut t_is = vec![];
    for i in 0..PERM_SIZE {
        // let tmp = product of t'_i from 0 to i
        let mut tmp = F::one();
        for j in 0..(i+1) {
            tmp = tmp * t_prime_is[j];
        }

        // Multiply by b_i to remove random masks
        let t_i = evaluator.scale(&b_is[i], tmp);       

        t_is.push((t_i.clone(), evaluator.get_wire(&t_i)));
    }

    // Commit to t(X)
    let t_shares : &Vec<F> = &t_is.clone()
        .into_iter()
        .map(|x| x.1)
        .collect();
    let t_share_poly = utils::interpolate_poly_over_mult_subgroup(&t_shares);
    let t_share_com = KZG10::commit_g1(pp, &t_share_poly);

    // Make sure t_com is hiding as well
    let hiding_t_com = t_share_com + alpha2_vanish_poly_share_com;
    let t_com = evaluator.add_g1_elements_from_all_parties(&hiding_t_com, &String::from("t")).await;

    let tx_by_omega_share_poly = utils::poly_domain_div_ω(&t_share_poly, &ω);

    // Need to show that t(X) / t(X/ω) = g(X) / h(X)
    // 24: Compute [d(X)] as [d(X)] = h(X) * [t(X)] − [g(X) * t(X/ω)]
    let h_t_share_poly = h_poly.mul(&t_share_poly);
    let g_tx_by_omega_share_poly = evaluator.share_poly_mult(
        g_share_poly.clone(), 
        tx_by_omega_share_poly.clone()
    ).await;
    
    let d_share_poly = h_t_share_poly.sub(&g_tx_by_omega_share_poly);

    // Compute q(X) and r(X) as quotient and remainder of d(X) / (X^64 - 1)
    // TOASSERT - Reconstructed r(X) should be 0
    let domain = GeneralEvaluationDomain::<F>::new(PERM_SIZE).unwrap();
    let (q_share_poly, _) = d_share_poly.divide_by_vanishing_poly(domain).unwrap();

    // Commit to q(X) - with all the extra terms from the hiding polynomials
    // q'(x) = q(x) - alpha1 * alpha2 * (x^PERM_SIZE - 1) + alpha2 * h(x) - alpha1 * t(x/w) - alpha2 * g(x)

    let q_share_com = KZG10::commit_g1(pp, &q_share_poly);
    
    // Computing alpha1 * alpha2 * (x^PERM_SIZE - 1)
    let h_alpha1_alpha2 = evaluator.mult(&alpha1, &alpha2).await;
    let alpha1_alpha2_vanish_poly_share_com = KZG10::commit_g1(pp, &vanishing_poly).mul(evaluator.get_wire(&h_alpha1_alpha2));
    
    // Computing alpha2 * h(x)
    let alpha2_h_share_poly = h_poly.mul(evaluator.get_wire(&alpha2));
    let alpha2_h_share_poly_com = KZG10::commit_g1(pp, &alpha2_h_share_poly);

    // Computing alpha1 * t(x/w)
    // First batch mult t_is with alpha1
    let h_alpha1_t_is = evaluator.batch_mult(
        &t_is.clone()
            .into_iter()
            .map(|x| x.0)
            .collect::<Vec<String>>(),
        &vec![alpha1.clone(); PERM_SIZE]
    ).await;
    
    let alpha1_t_is = h_alpha1_t_is
        .into_iter()
        .map(|handle| evaluator.get_wire(&handle))
        .collect::<Vec<F>>();

    // Then compute alpha1 * t(x/w)
    let alpha1_t_share_poly = utils::interpolate_poly_over_mult_subgroup(&alpha1_t_is);
    let alpha1_t_by_w_share_poly = utils::poly_domain_div_ω(&alpha1_t_share_poly, &ω);

    let alpha1_t_by_w_share_poly_com = KZG10::commit_g1(pp, &alpha1_t_by_w_share_poly);

    // Computing alpha2 * g(x)
    let h_alpha2_g_is = evaluator.batch_mult(
        &h_g_shares,
        &vec![alpha2.clone(); PERM_SIZE]
    ).await;

    let alpha2_g_is = h_alpha2_g_is
        .into_iter()
        .map(|handle| evaluator.get_wire(&handle))
        .collect::<Vec<F>>();

    // Compute alpha2 * g(x)
    let alpha2_g_share_poly = utils::interpolate_poly_over_mult_subgroup(&alpha2_g_is);
    let alpha2_g_share_poly_com = KZG10::commit_g1(pp, &alpha2_g_share_poly);

    let hiding_q_share_com = 
        q_share_com
        + alpha2_h_share_poly_com        
        - alpha1_alpha2_vanish_poly_share_com
        - alpha1_t_by_w_share_poly_com
        - alpha2_g_share_poly_com;

    let q_com = evaluator.add_g1_elements_from_all_parties(&hiding_q_share_com, &String::from("perm_q")).await;

    // Compute y2 = hash(v_com, f_com, q_com, t_com, g_com)
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();
    let mut q_bytes = Vec::new();
    let mut t_bytes = Vec::new();
    let mut g_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    f_com.serialize_uncompressed(&mut f_bytes).unwrap();
    q_com.serialize_uncompressed(&mut q_bytes).unwrap();
    t_com.serialize_uncompressed(&mut t_bytes).unwrap();
    g_com.serialize_uncompressed(&mut g_bytes).unwrap();

    let y2 = utils::fs_hash(vec![&v_bytes, &f_bytes, &q_bytes, &t_bytes, &g_bytes], 1)[0];

    // Compute polyevals and proofs
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w63 = utils::compute_power(&w, PERM_SIZE as u64 - 1);

    // Evaluate t(x) at w^63
    let h_y1 = evaluator.share_poly_eval(&t_share_poly, w63);
    // No adjustment from hiding term
    // let h_hiding_y1 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&w63));
    // let h_y1 = evaluator.add(&h_y1, &h_hiding_y1);
    
    // Evaluate t(x) at y2
    let h_y2_orig = evaluator.share_poly_eval(&t_share_poly, y2);
    // Adjustment from hiding term
    let h_hiding_y2 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&y2));
    let h_y2 = evaluator.add(&h_y2_orig, &h_hiding_y2);
    
    // Evaluate t(x) at y2 / w
    let h_y3_orig = evaluator.share_poly_eval(&t_share_poly, y2 / w);
    // Adjustment from hiding term
    let h_hiding_y3 = evaluator.scale(&alpha2, vanishing_poly.evaluate(&(y2 / w)));
    let h_y3 = evaluator.add(&h_y3_orig, &h_hiding_y3);
    
    // Evaluate g(x) at y2
    let h_y4_orig = evaluator.share_poly_eval(&g_share_poly, y2);
    // Adjustment from hiding term
    let h_hiding_y4 = evaluator.scale(&alpha1, vanishing_poly.evaluate(&y2));
    let h_y4 = evaluator.add(&h_y4_orig, &h_hiding_y4);
    
    // Evaluate q(x) at y2
    let h_y5_orig = evaluator.share_poly_eval(&q_share_poly, y2);
    // Adjustments from hiding terms
    let h_hiding_y5_1 = evaluator.scale(&h_alpha1_alpha2, vanishing_poly.evaluate(&y2));
    let h_hiding_y5_2 = evaluator.share_poly_eval(&alpha2_h_share_poly, y2);
    let h_hiding_y5_3 = evaluator.share_poly_eval(&alpha1_t_by_w_share_poly, y2);
    let h_hiding_y5_4 = evaluator.share_poly_eval(&alpha2_g_share_poly, y2);

    let temp1 = evaluator.add(&h_hiding_y5_3, &h_hiding_y5_4);
    let temp2 = evaluator.sub(&h_y5_orig, &temp1);
    let temp3 = evaluator.add(&temp2, &h_hiding_y5_2);
    let h_y5 = evaluator.sub(&temp3, &h_hiding_y5_1);
    
    // Compute proofs
    let pi_s = evaluator.batch_eval_proof_with_share_poly(
        pp, 
        &vec![t_share_poly.clone(), t_share_poly.clone(), t_share_poly.clone(), g_share_poly.clone(), q_share_poly.clone()],
        &vec![w63, y2, y2 / w, y2, y2]
    ).await;

    // Adjustments to proofs from hiding terms
    // pi_1
    let mut divisor = 
        DensePolynomial::from_coefficients_vec(vec![-w63, F::from(1)]);
    let (mut quotient, _) = 
        DenseOrSparsePolynomial::divide_with_q_and_r(
            &(&vanishing_poly).into(),
            &(&divisor).into(),
        ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_1 = pi_s[0].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_2
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_2 = pi_s[1].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_3
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-(y2 / w), F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
        
    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_3 = pi_s[2].clone() + pi_poly.mul(evaluator.get_wire(&alpha2));

    // pi_4
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_4 = pi_s[3].clone() + pi_poly.mul(evaluator.get_wire(&alpha1));

    // pi_5
    divisor = 
        DensePolynomial::from_coefficients_vec(vec![-y2, F::from(1)]);
    let (quotient_1, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly_1 = KZG10::commit_g1(pp, &quotient_1);
    let mut pi_5 = pi_s[4].clone() - pi_poly_1.mul(evaluator.get_wire(&h_alpha1_alpha2));

    let (quotient_2, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha2_h_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly_2 = KZG10::commit_g1(pp, &quotient_2);
    pi_5 = pi_5 + pi_poly_2;

    let (quotient_3, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha1_t_by_w_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();
    
    let pi_poly_3 = KZG10::commit_g1(pp, &quotient_3);
    pi_5 = pi_5 - pi_poly_3;

    let (quotient_4, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&alpha2_g_share_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly_4 = KZG10::commit_g1(pp, &quotient_4);
    pi_5 = pi_5 - pi_poly_4;

    let pi_is = evaluator.batch_add_g1_elements_from_all_parties(
        &vec![pi_1, pi_2, pi_3, pi_4, pi_5],
        &vec![String::from("pi_1"), String::from("pi_2"), String::from("pi_3"), String::from("pi_4"), String::from("pi_5")]
    ).await;

    (PermutationProof {
        y1: evaluator.output_wire(&h_y1).await,
        y2: evaluator.output_wire(&h_y2).await,
        y3: evaluator.output_wire(&h_y3).await,
        y4: evaluator.output_wire(&h_y4).await,
        y5: evaluator.output_wire(&h_y5).await,
        pi_1: pi_is[0].clone(),
        pi_2: pi_is[1].clone(),
        pi_3: pi_is[2].clone(),
        pi_4: pi_is[3].clone(),
        pi_5: pi_is[4].clone(),
        f_com,
        q_com,
        t_com
    },
    alpha1)
}

fn verify_permutation_argument(
    pp: &UniversalParams<Curve>,
    perm_proof: &PermutationProof,
) -> bool {
    let mut b = true;

    // Compute v(X) from powers of w
    let w = utils::multiplicative_subgroup_of_size(PERM_SIZE as u64);
    let w63 = utils::compute_power(&w, PERM_SIZE as u64 - 1);

    let v_evals: Vec<F> = (0..PERM_SIZE)
        .into_iter()
        .map(|i| utils::compute_power(&w, i as u64))
        .collect();

    let v = utils::interpolate_poly_over_mult_subgroup(&v_evals);
    let v_com = KZG10::commit_g1(pp, &v);

    // Compute hash1 and hash2
    let mut v_bytes = Vec::new();
    let mut f_bytes = Vec::new();
    let mut q_bytes = Vec::new();
    let mut t_bytes = Vec::new();
    let mut g_bytes = Vec::new();

    v_com.serialize_uncompressed(&mut v_bytes).unwrap();
    perm_proof.f_com.serialize_uncompressed(&mut f_bytes).unwrap();

    let hash1 = utils::fs_hash(vec![&v_bytes, &f_bytes], 1)[0];

    // Compute g_com from f_com
    let const_y1 = DensePolynomial::from_coefficients_vec(vec![hash1]);
    let const_com_y1 = KZG10::commit_g1(pp, &const_y1);

    let g_com = perm_proof.f_com.clone() + const_com_y1;

    perm_proof.q_com.serialize_uncompressed(&mut q_bytes).unwrap();
    perm_proof.t_com.serialize_uncompressed(&mut t_bytes).unwrap();
    g_com.serialize_uncompressed(&mut g_bytes).unwrap();

    let hash2 = utils::fs_hash(vec![&v_bytes, &f_bytes, &q_bytes, &t_bytes, &g_bytes], 1)[0];
    
    // Check all evaluation proofs
    b = b & utils::kzg_check(
        pp,
        &perm_proof.t_com,
        &w63,
        &perm_proof.y1,
        &perm_proof.pi_1
    );

    b = b & utils::kzg_check(
        pp,
        &perm_proof.t_com,
        &hash2,
        &perm_proof.y2,
        &perm_proof.pi_2
    );

    b = b & utils::kzg_check(
        pp,
        &perm_proof.t_com,
        &(hash2 / w),
        &perm_proof.y3,
        &perm_proof.pi_3
    );

    b = b & utils::kzg_check(
        pp,
        &g_com,
        &(hash2),
        &perm_proof.y4,
        &perm_proof.pi_4
    );

    b = b & utils::kzg_check(
        pp,
        &perm_proof.q_com,
        &hash2,
        &perm_proof.y5,
        &perm_proof.pi_5
    );

    // Check 0 : b = 1
    if ! b {
        println!("VerifyPerm - Check 0 failed");
    }

    // y1 = t(w^63)
    // y2 = t(hash2)
    // y3 = t(hash2 / w)
    // y4 = g(hash2)
    // y5 = q(hash2)
    // Check 1 : y2 * (v(hash2) + hash1) - y3 * y4 = y5 * (hash2^k - 1)
    let tmp1 = perm_proof.y2 * (v.evaluate(&hash2) + hash1);
    let tmp2 = perm_proof.y3 * perm_proof.y4;
    let tmp3 = perm_proof.y5 * (hash2.pow([PERM_SIZE as u64]) - F::one());

    b = b & (tmp1 - tmp2 == tmp3);

    if tmp1 - tmp2 != tmp3 {
        println!("VerifyPerm - Check 1 failed");
    }

    // Check 2 : y1 = 1
    b = b & (perm_proof.y1 == F::one());

    if perm_proof.y1 != F::one() {
        println!("VerifyPerm - Check 2 failed");
    }
    
    b
}


/// Produces ciphertexts and links the card commitment to the ciphertexts
async fn encrypt_and_prove(
    pp: &UniversalParams<Curve>,
    evaluator: &mut Evaluator,
    card_handles: Vec<String>,
    card_commitment: G1, // C = g^{\sum_i card_handles_i L_i(x) + alpha1 * (x^PERM_SIZE - 1)}
    alpha1: String,
    pk: G2,
    ids: Vec<BigUint>
) -> EncryptProof {
    // Get all cards from card handles
    let mut cards = vec![];
    for h in card_handles.clone() {
        cards.push(evaluator.get_wire(&h));
    }

    // Sample common randomness for encryption
    let r = evaluator.ran();

    let t_ibe = Instant::now();
    // Encrypt the cards to ids with the same pk
    let (c1, c2s) = evaluator.batch_dist_ibe_encrypt_with_common_mask(
        &card_handles, 
        &r, 
        &pk, 
        ids.as_slice()
    ).await;
    println!("encryption: {:?}", t_ibe.elapsed());

    // Encrypt an extra "card" with alpha1
    // This id can be anything (different from the others), it will never be opened.
    let (_, alpha1_c2) = evaluator.dist_ibe_encrypt(
        &alpha1, 
        &r, 
        &pk, 
        BigUint::from(123 as u64)
    ).await; 

    let t_ctxt_proof = Instant::now();

    // Hash all the encryptions to get randomness for batching
    let mut bytes = Vec::new();
    let mut c1_bytes = Vec::new();
    let mut c2_bytes = Vec::new();

    c1.serialize_uncompressed(&mut c1_bytes).unwrap();
    bytes.extend_from_slice(&c1_bytes);

    for i in 0..PERM_SIZE {
        c2s[i].serialize_uncompressed(&mut c2_bytes).unwrap();
        bytes.extend_from_slice(&c2_bytes);
    }

    // Add alpha1 ciphertext to the hash
    alpha1_c2.serialize_uncompressed(&mut c2_bytes).unwrap();
    bytes.extend_from_slice(&c2_bytes);

    // define delta
    let delta = utils::fs_hash(vec![&bytes], 1)[0];

    // Evaluate the card commitment at delta and produce opening proof
    // Modified to take into account the hiding term
    let card_poly = utils::interpolate_poly_over_mult_subgroup(&cards);
    let vanishing_poly = utils::compute_vanishing_poly(PERM_SIZE as usize);

    // Evaluate polynomial at delta, taking into account the hiding term
    let h_poly_eval_orig = evaluator.share_poly_eval(&card_poly, delta);
    let h_hiding = evaluator.scale(&alpha1, vanishing_poly.evaluate(&delta));

    let h_poly_eval = evaluator.add(&h_poly_eval_orig, &h_hiding);
    let poly_eval = evaluator.output_wire(&h_poly_eval).await;
    
    // Produce opening proof - share
    let pi_orig = evaluator.eval_proof_with_share_poly(
        pp, 
        card_poly, 
        delta
    ).await;

    // divisor(x) = x - delta for the KZG opening proof
    let divisor = 
        DensePolynomial::from_coefficients_vec(vec![-delta, F::from(1)]);
    let (quotient, _) = 
            DenseOrSparsePolynomial::divide_with_q_and_r(
                &(&vanishing_poly).into(),
                &(&divisor).into(),
            ).unwrap();

    let pi_poly = KZG10::commit_g1(pp, &quotient);
    let pi_share = pi_orig.clone() + pi_poly.mul(evaluator.get_wire(&alpha1)); 

    // reconstruct the quotient polynomial
    let pi = evaluator.add_g1_elements_from_all_parties(&pi_share, &String::from("new_enc_prove_pi")).await;

    // Batch the pairing bases
    // Evaluate lagrange basis at delta
    let mut lagrange_delta = Vec::new();
    for i in 0..PERM_SIZE {
        lagrange_delta.push(utils::compute_lagrange_basis(i as u64, PERM_SIZE as u64).evaluate(&delta));
    }

    // Computing E = prod_i e_i^Li(delta)
    let mut batch_h = G1::zero();
    for i in 0..PERM_SIZE {
        // TODO: fix this. Need proper hash to curve
        let x_f = F::from(ids[i].clone());
        let hash_id = G1::generator().mul(x_f);
        batch_h = batch_h.add(hash_id.mul(lagrange_delta[i]));
    }
    // Add the contribution from the hiding term (multiplied with (delta^PERM_SIZE - 1))
    let x_f = F::from(BigUint::from(123 as u64));
    let hash_id = G1::generator().mul(x_f);
    batch_h = batch_h.add(hash_id.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1)));

    let e_batch = <Curve as Pairing>::pairing(batch_h, pk);

    // Compute t = e_batch^r
    let t = evaluator.exp_and_reveal_gt(
        vec![e_batch], 
        vec![r.clone()], 
        &String::from("new_enc_prove_t")
    ).await;

    // Sigma protocol to show that t = e_batch^r and c1 = g^r
    // Message 1
    // a1 = g^z
    // a2 = e_batch^z

    let z = evaluator.ran();
    let a1 = evaluator.exp_and_reveal_g2(
        vec![G2::generator()], 
        vec![z.clone()], 
        &String::from("new_enc_prove_a1")
    ).await;
    let a2 = evaluator.exp_and_reveal_gt(
        vec![e_batch], 
        vec![z.clone()], 
        &String::from("new_enc_prove_a2")
    ).await;

    // Message 2 - FS Hash of a1,a2
    let (mut a1_bytes, mut a2_bytes): (Vec<u8>, Vec<u8>) 
        = (Vec::new(),Vec::new());
    
    a1.serialize_uncompressed(&mut a1_bytes).unwrap();
    a2.serialize_uncompressed(&mut a2_bytes).unwrap();

    let eta = utils::fs_hash(vec![&a1_bytes, &a2_bytes], 1);

    // Message 3
    let mut h_y = evaluator.scale(&r, eta[0]);
    h_y = evaluator.add(&h_y, &z);
    let y = evaluator.output_wire(&h_y).await;

    println!("ctxt proof: {:?}", t_ctxt_proof.elapsed());

    EncryptProof{
        pk: pk,
        ids: ids,
        card_commitment: card_commitment,
        card_poly_eval: poly_eval,
        eval_proof: pi,
        ciphertexts: (c1, c2s),
        hiding_ciphertext: alpha1_c2,
        t: t,
        sigma_proof: Some(SigmaProof{
            a1: a1,
            a2: a2,
            eta: eta[0],
            y: y
        })
    }

}

async fn local_verify_encryption_proof(
    pp: &UniversalParams<Curve>,
    proof: &EncryptProof,
) -> bool {
    let mut b = true;

    // Common first element of all ciphertexts
    let c1 = proof.ciphertexts.0.clone();

    // Compute delta
    let mut bytes = Vec::new();
    let mut c1_bytes = Vec::new();
    let mut c2_bytes = Vec::new();

    c1.serialize_uncompressed(&mut c1_bytes).unwrap();
    bytes.extend_from_slice(&c1_bytes);

    for i in 0..PERM_SIZE {
        proof.ciphertexts.1[i].serialize_uncompressed(&mut c2_bytes).unwrap();
        bytes.extend_from_slice(&c2_bytes);
    }

    // Add alpha1 ciphertext to the hash
    proof.hiding_ciphertext.serialize_uncompressed(&mut c2_bytes).unwrap();
    bytes.extend_from_slice(&c2_bytes);

    let delta = utils::fs_hash(vec![&bytes], 1)[0];

    // Check evaluation proof
    if ! utils::kzg_check(
        pp,
        &proof.card_commitment,
        &delta,
        &proof.card_poly_eval,
        &proof.eval_proof
    ) {
        b = false;
    }

    // Compute e_batch
    let mut lagrange_delta = Vec::new();
    for i in 0..PERM_SIZE {
        lagrange_delta.push(utils::compute_lagrange_basis(i as u64, PERM_SIZE as u64).evaluate(&delta));
    }

    let mut batch_h = G1::zero();
    for i in 0..PERM_SIZE {
        // TODO: fix this. Need proper hash to curve
        let x_f = F::from(proof.ids[i].clone());
        let hash_id = G1::generator().mul(x_f);
        batch_h = batch_h.add(hash_id.mul(lagrange_delta[i]));
    }
    // Add the contribution from the hiding term (multiplied with (delta^PERM_SIZE - 1))
    let x_f = F::from(BigUint::from(123 as u64));
    let hash_id = G1::generator().mul(x_f);
    batch_h = batch_h.add(hash_id.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1)));

    let e_batch = <Curve as Pairing>::pairing(batch_h, proof.pk);

    // Check that prod_i c2_i^Li(delta) * alpha1_c2*(delta*PERM_SIZE - 1) = g^f(delta) * t
    let mut lhs = Gt::zero();
    for i in 0..PERM_SIZE {
        lhs = lhs + proof.ciphertexts.1[i].mul(lagrange_delta[i]);
    }
    lhs = lhs + proof.hiding_ciphertext.mul(utils::compute_power(&delta, PERM_SIZE as u64) - F::from(1));

    let mut rhs = Gt::generator().mul(proof.card_poly_eval);
    rhs = rhs.add(proof.t);

    if ! lhs.eq(&rhs) {
        b = false;
    }

    // Check sigma proof
    // Compute hash to get eta
    let (mut a1_bytes, mut a2_bytes): (Vec<u8>, Vec<u8>) 
        = (Vec::new(),Vec::new());

    proof.sigma_proof.as_ref().unwrap().a1.serialize_uncompressed(&mut a1_bytes).unwrap();
    proof.sigma_proof.as_ref().unwrap().a2.serialize_uncompressed(&mut a2_bytes).unwrap();

    let eta = utils::fs_hash(vec![&a1_bytes, &a2_bytes], 1);

    // Check statement 1
    let lhs = G2::generator().mul(proof.sigma_proof.as_ref().unwrap().y);
    let rhs = c1.mul(eta[0]).add(proof.sigma_proof.as_ref().unwrap().a1);

    if ! lhs.eq(&rhs) {
        b = false;
    }

    // Check statement 2
    let lhs = e_batch.mul(proof.sigma_proof.as_ref().unwrap().y);
    let rhs = proof.t.mul(eta[0]).add(proof.sigma_proof.as_ref().unwrap().a2);

    if ! lhs.eq(&rhs) {
        b = false;
    }

    b
}

/// Estimating time to decrypt one card at game time
pub fn decrypt_one_card(
    index: usize,
    decryption_key: &G1, // Should be sk * H(id)
    proof: &EncryptProof,
    cache: &[Gt],
) -> Option<usize> {
    let ciphertext = (proof.ciphertexts.0, proof.ciphertexts.1[index].clone());

    // IBE decryption to get g^mask
    let (c1, c2) = ciphertext;
    let div = <Curve>::pairing(decryption_key, c1);

    let exp_mask = c2.sub(div);

    for i in 0..cache.len() {
        if exp_mask.eq(&cache[i]) {
            return Some(i);
        }
    }

    return None;
}

