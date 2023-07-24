
use futures::{prelude::*, channel::*};
use std::time::Duration;
use async_std::task;

use crate::address_book::*;
use crate::common::*;

macro_rules! send_over_network {
    ($msg:expr, $tx:expr) => {
        let r = $tx.send($msg).await;
        if let Err(err) = r {
            eprint!("evaluator error {:?}", err);
        }
    };
}

pub struct Evaluator {
    id: Pok3rPeerId,
    tx: mpsc::UnboundedSender<String>,
    rx: mpsc::UnboundedReceiver<String>,
}

impl Evaluator {
    pub async fn new(
        id: &Pok3rPeerId,
        _addr_book: &Pok3rAddrBook,
        tx: mpsc::UnboundedSender<String>, 
        mut rx: mpsc::UnboundedReceiver<String>
    ) -> Self {
        let msg: String = rx.select_next_some().await;
        println!("evaluator expecting connection, got: {}", msg);

        task::block_on(async {
            task::sleep(Duration::from_secs(1)).await;
            println!("After sleeping for 1 second.");
        });

        Evaluator { 
            id: id.clone(), 
            tx: tx, 
            rx: rx
        }
    }

    pub async fn test_networking(&mut self) {
        let greeting = format!("Hello from {}", self.id);
        //now do the MPC
        send_over_network!(greeting, self.tx);
        //send_over_network!(String::from("Hellloooo from me"), tx);
        
        let msg: String = self.rx.select_next_some().await;
        println!("evaluator received: {}", msg);
        let msg: String = self.rx.select_next_some().await;
        println!("evaluator received: {}", msg);
    }

}

