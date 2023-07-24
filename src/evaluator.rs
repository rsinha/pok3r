
use futures::{prelude::*, channel::*};
use std::error::Error;
use std::time::Duration;
use async_std::task;

use crate::address_book::*;


macro_rules! send_over_network {
    ($msg:expr, $tx:expr) => {
        let r = $tx.send($msg).await;
        if let Err(err) = r {
            eprint!("evaluator error {:?}", err);
        }
    };
}

pub async fn run_evaluator_daemon(
    id: &Pok3rPeerId,
    _addr_book: &Pok3rAddrBook,
    tx: &mut mpsc::UnboundedSender<String>, 
    rx: &mut mpsc::UnboundedReceiver<String>) -> Result<(), Box<dyn Error>> {

    //first wait for a ready signal from the networking daemon
    let msg: String = rx.select_next_some().await;
    println!("evaluator expecting connection, got: {}", msg);

    task::block_on(async {
        task::sleep(Duration::from_secs(1)).await;
        println!("After sleeping for 1 second.");
    });

    let greeting = format!("Hello from {}", id);
    //now do the MPC
    send_over_network!(greeting, tx);
    //send_over_network!(String::from("Hellloooo from me"), tx);
    
    let msg: String = rx.select_next_some().await;
    println!("evaluator received message: {}", msg);
    let msg: String = rx.select_next_some().await;
    println!("evaluator received: {}", msg);

    Ok(())
}