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

mod completion;
mod distribute;
mod transmit;
mod worker;

pub(crate) use self::completion::*;
pub(crate) use self::distribute::*;
pub(crate) use self::transmit::*;
pub(crate) use self::worker::*;

use crate::dpdk2::LcoreId;
use async_std::task;
use std::cmp;
use std::collections::HashMap;
use std::time::Duration;

/// A task to spawn when bootstrapping the runtime.
pub(crate) enum BootstrapTask {
    CompletionRx(CompletionRx),
    DistributeRx(DistributeRx),
    PipelineWorker(PipelineWorker),
    Transmit(Transmit),
}

impl BootstrapTask {
    /// Spawns the task onto the thread-local executor.
    pub(crate) fn spawn_local(self) {
        match self {
            BootstrapTask::CompletionRx(task) => task.spawn_local(),
            BootstrapTask::DistributeRx(task) => task.spawn_local(),
            BootstrapTask::PipelineWorker(task) => task.spawn_local(),
            BootstrapTask::Transmit(task) => task.spawn_local(),
        }
    }
}

impl From<CompletionRx> for BootstrapTask {
    fn from(task: CompletionRx) -> Self {
        BootstrapTask::CompletionRx(task)
    }
}

impl From<DistributeRx> for BootstrapTask {
    fn from(task: DistributeRx) -> Self {
        BootstrapTask::DistributeRx(task)
    }
}

impl From<PipelineWorker> for BootstrapTask {
    fn from(task: PipelineWorker) -> Self {
        BootstrapTask::PipelineWorker(task)
    }
}

impl From<Transmit> for BootstrapTask {
    fn from(task: Transmit) -> Self {
        BootstrapTask::Transmit(task)
    }
}

/// Bootstrap tasks by lcore.
pub(crate) struct BootstrapTasks {
    tasks: HashMap<LcoreId, Vec<BootstrapTask>>,
}

impl BootstrapTasks {
    pub(crate) fn new() -> Self {
        BootstrapTasks {
            tasks: HashMap::new(),
        }
    }

    pub(crate) fn push(&mut self, lcore: LcoreId, task: BootstrapTask) {
        self.tasks.entry(lcore).or_insert_with(Vec::new).push(task);
    }

    pub(crate) fn take(&mut self, lcore: LcoreId) -> Option<Vec<BootstrapTask>> {
        self.tasks.remove(&lcore)
    }
}

/// Simple sleep with an exponential backoff up to 1 millisecond.
async fn backoff(dur: &mut Duration) {
    let local = *dur;
    task::sleep(local).await;

    const THRESHOLD: Duration = Duration::from_millis(1);
    if local < THRESHOLD {
        *dur = cmp::min(local * 2, THRESHOLD);
    }
}
