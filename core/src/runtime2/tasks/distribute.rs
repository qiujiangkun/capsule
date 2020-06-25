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
use crate::dpdk2::{Distributor, LcoreId, PortRxQueue};
use async_std::task;
use smol::Task;
use std::time::Duration;

/// Distributor based RX task.
///
/// The distributor model polls the RX queue in a loop and then distributes
/// the packets to the worker lcores.
pub(crate) struct DistributeRx {
    rxq: PortRxQueue,
    dist: Distributor,
    burst: usize,
}

impl DistributeRx {
    pub(crate) fn new(rxq: PortRxQueue, dist: Distributor, burst: usize) -> Self {
        DistributeRx { rxq, dist, burst }
    }

    /// Spawns the task onto the thread-local executor.
    pub(crate) fn spawn_local(self) {
        let lcore = LcoreId::current();
        let DistributeRx {
            rxq,
            mut dist,
            burst,
        } = self;

        debug!(?lcore, ?rxq, "spawning distribute rx.");

        Task::local(async move {
            debug!(?lcore, ?rxq, "executing distribute rx.");
            let mut packets = Vec::with_capacity(burst);
            let mut wait = Duration::from_micros(1);

            loop {
                rxq.receive(&mut packets);

                if !packets.is_empty() {
                    // resets the backoff duration.
                    wait = Duration::from_micros(1);

                    dist.process(&mut packets);

                    // cooperatively moves to the back of the execution queue,
                    // making room for other tasks before polling rx again.
                    task::yield_now().await;
                } else {
                    // flush the packets in the backlog. they may be stuck in
                    // between the poll cycles of the distributor and the
                    // workers.
                    dist.flush();

                    // exponentially backs off.
                    super::backoff(&mut wait).await;
                }
            }
        })
        .detach();
    }
}
