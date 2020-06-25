/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use crate::dpdk2::{LcoreId, Mbuf, PortTxQueue};
use crate::{debug, error};
use async_std::task;
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::prelude::*;
use smol::Task;

/// TX task.
///
/// TX collates packets from all lcores using an unbounded channel.
pub(crate) struct Transmit {
    txq: PortTxQueue,
    receiver: UnboundedReceiver<Mbuf>,
    burst: usize,
}

impl Transmit {
    pub(crate) fn spawn_local(self) {
        let lcore = LcoreId::current();
        let Transmit {
            txq,
            mut receiver,
            burst,
        } = self;

        debug!(?lcore, ?txq, "spawning tx.");

        Task::local(async move {
            debug!(?lcore, ?txq, "executing tx.");
            let mut packets = Vec::with_capacity(burst);

            loop {
                if let Some(packet) = receiver.next().await {
                    packets.push(packet.into_ptr());

                    // try to batch the packets up to burst size.
                    for _ in 1..burst {
                        match receiver.try_next() {
                            Ok(Some(packet)) => packets.push(packet.into_ptr()),
                            // should never happen, see below.
                            Ok(None) => error!(?lcore, ?txq, "unbounded channel closed."),
                            // no more packets to batch, ready to transmit.
                            Err(_) => break,
                        }
                    }

                    txq.transmit(&mut packets);

                    // cooperatively moves to the back of the execution queue,
                    // making room for other tasks before transmitting again.
                    task::yield_now().await;
                } else {
                    // this branch can only be reached if `next` returns none,
                    // indicating that the channel has been closed from the sender
                    // side. but this should never happen.
                    error!(?lcore, ?txq, "unbounded channel closed.");
                }
            }
        })
        .detach();
    }
}

/// Creates a new transmit task with the corresponding sender.
pub(crate) fn transmit_task(txq: PortTxQueue, burst: usize) -> (UnboundedSender<Mbuf>, Transmit) {
    let (sender, receiver) = mpsc::unbounded::<Mbuf>();
    (
        sender,
        Transmit {
            txq,
            receiver,
            burst,
        },
    )
}
