use std::{thread, collections::*};
use async_std::task;
use futures::channel::*;
use clap::Parser;
use num_bigint::BigUint;
use serde_json::json;

mod network;
mod evaluator;
mod address_book;
mod common;
mod utils;
mod kzg;
mod encoding;
mod shuffler;

use address_book::*;
use evaluator::*;
use common::*;
use shuffler::*;


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
        task::sleep(std::time::Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    // KZG setup runs once
    let pp = compute_params();

    // Actual protocol
    let card_share_handles = shuffle_deck(&mut mpc).await;
    println!("Generated a deck of {} cards", card_share_handles.len());
    
    let (perm_proof, alpha1) = compute_permutation_argument(
        &pp, 
        &mut mpc, 
        &card_share_handles,
    ).await;

    // Get a random public key pk in G2 - for testing (should be generated by DKG)
    // FIXME: Implement DKG to generate the public key
    let (msk, mpk) = compute_keyper_keys();

    // Get random ids as byte strings
    let ids = (0..PERM_SIZE)
        .into_iter()
        .map(|i| BigUint::from(i as u64))
        .collect::<Vec<BigUint>>();

    // Encrypt and prove
    //let s_encrypt = Instant::now();
    let encrypt_proof = encrypt_and_prove(
        &pp, 
        &mut mpc, 
        card_share_handles.clone(), 
        perm_proof.f_com, 
        alpha1,
        mpk,
        ids.clone()
    ).await;

    // decrypt all cards
    let cache = compute_decryption_cache();
    let mut decrypted_cards = Vec::new();
    for i in 0..PERM_SIZE {
        let dec_key = compute_decryption_key(&ids[i], msk);

        // ignore the first (PERM_SIZE - DECK_SIZE) cards, which are not part of deck
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
