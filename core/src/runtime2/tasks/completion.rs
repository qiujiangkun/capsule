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
use crate::dpdk2::{LcoreId, Mbuf, PortRxQueue};
use async_std::task;
use failure::Fallible;
use smol::Task;
use std::sync::Arc;
use std::time::Duration;

/// Run-to-completion RX task.
///
/// The run-to-completion model polls the RX queue in a loop and executes
/// the per packet pipeline on the same lcore.
pub(crate) struct CompletionRx {
    rxq: PortRxQueue,
    f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
    burst: usize,
}

impl CompletionRx {
    pub(crate) fn new(
        rxq: PortRxQueue,
        f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
        burst: usize,
    ) -> Self {
        CompletionRx { rxq, f, burst }
    }

    /// Spawns the task onto the thread-local executor.
    pub(crate) fn spawn_local(self) {
        let lcore = LcoreId::current();
        let CompletionRx { rxq, f, burst } = self;

        debug!(?lcore, ?rxq, "spawning run-to-completion rx.");

        Task::local(async move {
            debug!(?lcore, ?rxq, "executing run-to-completion rx.");
            let mut packets = Vec::with_capacity(burst);
            let mut wait = Duration::from_micros(1);

            loop {
                rxq.receive(&mut packets);

                if !packets.is_empty() {
                    for packet in packets.drain(..) {
                        let mbuf = unsafe { Mbuf::from_ptr(packet) };
                        let _ = f(mbuf);
                    }

                    // cooperatively moves to the back of the execution queue,
                    // making room for other tasks before polling rx again.
                    task::yield_now().await;
                } else {
                    // exponentially backs off.
                    super::backoff(&mut wait).await;
                }
            }
        })
        .detach();
    }
}
