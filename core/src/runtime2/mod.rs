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

mod shutdown;
mod tasks;

use self::shutdown::Shutdown;
use self::tasks::{BootstrapTask, CompletionRx, DistributeRx, PipelineWorker};
use crate::config2::RuntimeConfig;
use crate::dpdk2::{self, JoinHandle, LcoreId, Mbuf, Mempool, Port, PortBuilder};
use crate::{debug, info};
use failure::Fallible;
use std::collections::HashMap;
use std::fmt;
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing tasks.
pub struct Runtime2 {
    mempool: ManuallyDrop<Mempool>,
    ports: HashMap<String, Port>,
    worker_cores: Vec<LcoreId>,
    pipelines: HashMap<String, Arc<dyn Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static>>,
}

impl Runtime2 {
    /// Initializes a new runtime from config settings.
    #[allow(clippy::cognitive_complexity)]
    pub fn from_config(config: RuntimeConfig) -> Fallible<Self> {
        info!("initializing EAL...");
        dpdk2::eal_init(config.to_eal_args())?;

        info!("initializing mempool...");
        let socket = LcoreId::main().socket();
        let mut mempool = Mempool::new(
            "mempool",
            config.mempool.capacity,
            config.mempool.cache_size,
            socket,
        )?;
        debug!(?mempool);

        info!("initializing ports...");
        let mut ports = HashMap::new();
        for pconf in config.ports.iter() {
            let mut builder = PortBuilder::new(&pconf.name, &pconf.device)?;
            builder
                .set_rxq_txq_capacity(pconf.rxq_capacity, pconf.txq_capacity)?
                .set_promiscuous(pconf.promiscuous)?
                .set_multicast(pconf.multicast)?;

            if !pconf.rx_cores.is_empty() {
                builder.set_rx_lcores(pconf.rx_cores.clone(), pconf.use_workers)?;
            }
            if let Some(tx_core) = pconf.tx_core {
                builder.set_tx_lcores(vec![tx_core])?;
            }

            let port = builder.finish(&mut mempool)?;

            debug!(?port);
            ports.insert(port.name().to_owned(), port);
        }

        info!("runtime ready.");

        Ok(Runtime2 {
            mempool: ManuallyDrop::new(mempool),
            ports,
            worker_cores: config.worker_cores,
            pipelines: HashMap::new(),
        })
    }

    /// Sets the pipeline for a port identified by its logical name.
    pub fn set_port_pipeline<S, F>(mut self, port: S, pipeline: F) -> Self
    where
        S: Into<String>,
        F: Fn(Mbuf) -> Fallible<()> + Send + Sync + 'static,
    {
        let port = port.into();
        self.pipelines.insert(port, Arc::new(pipeline));
        self
    }

    fn bootstrap_tasks(&self) -> HashMap<LcoreId, Vec<BootstrapTask>> {
        const RX_BURST_SIZE: usize = 4;

        let mut tasks: HashMap<LcoreId, Vec<BootstrapTask>> = HashMap::new();

        self.ports.iter().for_each(|(name, port)| {
            let rxqs = port.get_rxqs();

            // the port doesn't have any rx.
            if rxqs.is_empty() {
                return;
            }

            if port.use_workers() {
                // constructs rx tasks for distributor model.
                let (dist, workers) =
                    dpdk2::distributor(name, port.port_id().socket(), self.worker_cores.len())
                        .unwrap(); //TODO:
                let pipeline = self.pipelines.get(name).unwrap(); //TODO:
                let (lcore, rxq) = rxqs.into_iter().next().unwrap(); //TODO:

                self.worker_cores
                    .iter()
                    .zip(workers.into_iter())
                    .for_each(|(lcore, worker)| {
                        tasks
                            .entry(*lcore)
                            .or_insert_with(Vec::new)
                            .push(PipelineWorker::new(worker, pipeline.clone()).into());
                    });

                tasks
                    .entry(lcore)
                    .or_insert_with(Vec::new)
                    .push(DistributeRx::new(rxq, dist, RX_BURST_SIZE).into());
            } else {
                // constructs rx tasks for run to completion model.
                let pipeline = self.pipelines.get(name).unwrap(); //TODO:
                rxqs.into_iter().for_each(|(lcore, rxq)| {
                    tasks
                        .entry(lcore)
                        .or_insert_with(Vec::new)
                        .push(CompletionRx::new(rxq, pipeline.clone(), RX_BURST_SIZE).into());
                });
            }
        });

        tasks
    }

    /// Starts the runtime execution.
    pub fn execute(self) -> Fallible<RuntimeGuard> {
        let mut handles = Vec::new();
        let (shutdown, wait) = Shutdown::new();
        let mut tasks = self.bootstrap_tasks();
        static STARTED: AtomicUsize = AtomicUsize::new(0);

        for id in LcoreId::iter(true) {
            let shutdown = wait.clone();
            let tasks = tasks.remove(&id);
            let handle = dpdk2::spawn(id, move || {
                smol::run(async move {
                    let lcore = LcoreId::current();
                    debug!(?lcore, "starting core.");

                    if let Some(tasks) = tasks {
                        debug!(?lcore, n = tasks.len(), "spawning bootstrap tasks.");
                        tasks.into_iter().for_each(BootstrapTask::spawn_local);
                    }

                    // marks the lcore as started.
                    STARTED.fetch_add(1, Ordering::Relaxed);
                    debug!(?lcore, "core started.");

                    shutdown.wait().await;
                    debug!(?lcore, "core shut down.");
                })
            })?;
            handles.push(handle);
        }

        // waits for all the lcores to start.
        while STARTED.load(Ordering::Relaxed) != handles.len() {}

        for port in self.ports.values() {
            port.start()?;
        }

        Ok(RuntimeGuard {
            runtime: self,
            lcores: handles,
            shutdown,
        })
    }
}

impl fmt::Debug for Runtime2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("mempool", &self.mempool)
            .field("ports", &self.ports)
            .field("worker_cores", &self.worker_cores)
            .finish()
    }
}

/// The RAII guard to stop and cleanup the runtime resources on drop.
pub struct RuntimeGuard {
    runtime: Runtime2,
    lcores: Vec<JoinHandle<()>>,
    shutdown: Shutdown,
}

impl Drop for RuntimeGuard {
    #[allow(clippy::cognitive_complexity)]
    fn drop(&mut self) {
        info!("shutting down runtime...");

        // triggers the shutdown of all running lcores.
        self.shutdown.signal();

        for lcore in self.lcores.drain(..) {
            // waiting on each lcore to finish shutting down.
            let _ = lcore.join();
        }

        // the default rust drop order is self before fields, which is the wrong
        // order for what we need. To control the order, we manually drop some
        // fields first.
        for (_, port) in self.runtime.ports.drain() {
            port.stop();
            port.close();
        }

        unsafe {
            ManuallyDrop::drop(&mut self.runtime.mempool);
        }

        debug!("freeing EAL...");
        let _ = dpdk2::eal_cleanup();
        info!("runtime shutdown.");
    }
}

impl fmt::Debug for RuntimeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RuntimeGuard")
    }
}
