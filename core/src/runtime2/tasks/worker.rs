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
use crate::dpdk2::{LcoreId, Mbuf, Worker, DISTRIBUTOR_BURST};
use async_std::task;
use failure::Fallible;
use smol::Task;
use std::sync::Arc;
use std::time::Duration;

/// Packet pipeline worker task.
///
/// Worker polls the distributor for packets to process.
pub(crate) struct PipelineWorker {
    worker: Worker,
    f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
}

impl PipelineWorker {
    pub(crate) fn new(
        worker: Worker,
        f: Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>,
    ) -> Self {
        PipelineWorker { worker, f }
    }
}

impl PipelineWorker {
    /// Spawns the task onto the thread-local executor.
    pub(crate) fn spawn_local(self) {
        let lcore = LcoreId::current();
        let PipelineWorker { mut worker, f } = self;

        debug!(?lcore, ?worker, "spawning pipeline worker.");

        Task::local(async move {
            debug!(?lcore, ?worker, "executing pipeline worker.");
            let mut packets = Vec::with_capacity(DISTRIBUTOR_BURST);
            let mut wait = Duration::from_micros(1);

            loop {
                worker.request();
                worker.poll(&mut packets);

                if !packets.is_empty() {
                    // resets the backoff duration.
                    wait = Duration::from_micros(1);

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
