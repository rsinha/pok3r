
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
    addr_book: Pok3rAddrBook,
    tx: mpsc::UnboundedSender<EvalNetMsg>,
    rx: mpsc::UnboundedReceiver<EvalNetMsg>,
}

impl Evaluator {
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

        task::block_on(async {
            task::sleep(Duration::from_secs(1)).await;
            println!("After sleeping for 1 second.");
        });

        Evaluator { 
            id: id.clone(),
            addr_book: addr_book,
            tx: tx, 
            rx: rx
        }
    }

    pub async fn test_networking(&mut self) {
        let greeting = EvalNetMsg::Greeting { message: format!("Hello from {}", self.id) };
        send_over_network!(greeting, self.tx);
        //send_over_network!(String::from("Hellloooo from me"), tx);

        //we expect greetings from all other players
        let num_other_parties = self.addr_book.len() - 1;
        for _ in 0..num_other_parties {
            let msg: EvalNetMsg = self.rx.select_next_some().await;
            //println!("evaluator got {:?}", msg);
            match msg {
                EvalNetMsg::Greeting { message } => { println!("evaluator parsed: {:?}", message); },
                _ => continue,
            }
        }
    }

}

