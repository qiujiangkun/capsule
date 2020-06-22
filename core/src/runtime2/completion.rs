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

use crate::debug;
use crate::dpdk2::{Mbuf, PortRxQueue};
use async_std::task;
use failure::Fallible;
use smol::Task;
use std::sync::Arc;

/// A run-to-completion RX task.
pub(crate) struct CompletionRx {
    rxq: PortRxQueue,
    f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
    batch: usize,
}

impl CompletionRx {
    pub(crate) fn new(
        rxq: PortRxQueue,
        f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
        batch: usize,
    ) -> Self {
        CompletionRx { rxq, f, batch }
    }
}

impl CompletionRx {
    /// Spawns the rx onto the thread-local executor.
    pub(crate) fn spawn_local(self) {
        let CompletionRx { rxq, f, batch } = self;
        debug!(queue = ?rxq, "spawning run-to-completion rx.");

        Task::local(Box::pin(async move {
            debug!(queue = ?rxq, "executing run-to-completion rx.");
            let mut packets = Vec::with_capacity(batch);

            loop {
                rxq.receive(&mut packets);

                if !packets.is_empty() {
                    for packet in packets.drain(..) {
                        let mbuf = unsafe { Mbuf::from_ptr(packet.as_ptr()) };
                        let _ = f(mbuf);
                    }
                }

                task::yield_now().await;
            }
        }))
        .detach();
    }
}
