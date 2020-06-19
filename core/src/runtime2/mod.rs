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

use crate::config2::RuntimeConfig;
use crate::dpdk2::{self, LcoreId, Mempool, Port, PortBuilder};
use crate::{debug, info};
use failure::Fallible;
use std::collections::HashMap;
use std::fmt;
use std::mem::ManuallyDrop;

/// The Capsule runtime.
///
/// The runtime initializes the underlying DPDK environment, and it also manages
/// the task scheduler that executes the packet processing tasks.
pub struct Runtime2 {
    mempool: ManuallyDrop<Mempool>,
    ports: HashMap<String, Port>,
    worker_cores: Vec<LcoreId>,
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

            if let Some(rx_core) = pconf.rx_core {
                builder.set_rx_lcores(vec![rx_core])?;
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
            worker_cores: config.cores,
        })
    }

    /// Starts the runtime execution.
    pub fn execute(self) -> Fallible<RuntimeGuard> {
        Ok(RuntimeGuard { runtime: self })
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

/// The RAII guard to cleanup the runtime resources on drop.
pub struct RuntimeGuard {
    runtime: Runtime2,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        // the default rust drop order is self before fields, which is the wrong
        // order for what EAL needs. To control the order, we manually drop some
        // fields first.
        unsafe {
            ManuallyDrop::drop(&mut self.runtime.mempool);
        }

        for (_, port) in self.runtime.ports.drain() {
            port.close();
        }

        debug!("freeing EAL...");
        let _ = dpdk2::eal_cleanup();
        info!("runtime shutdown.");
    }
}

impl fmt::Debug for RuntimeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeGuard").finish()
    }
}
