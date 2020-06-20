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

//! Toml-based configuration for use with Capsule applications.
//!
//! # Example
//!
//! A configuration from our [`pktdump`] example:
//! ```
//! app_name = "pktdump"
//! main_core = 0
//! cores = [0]
//!
//! [mempool]
//!     capacity = 65535
//!     cache_size = 256
//!
//! [[ports]]
//!     name = "eth1"
//!     device = "net_pcap0"
//!     args = "rx_pcap=tcp4.pcap,tx_iface=lo"
//!     rx_core = 0
//!     tx_core = 0
//!
//! [[ports]]
//!     name = "eth2"
//!     device = "net_pcap1"
//!     args = "rx_pcap=tcp6.pcap,tx_iface=lo"
//!     rx_core = 0
//!     tx_core = 0
//! ```
//!
//! [`pktdump`]: https://github.com/capsule-rs/capsule/tree/master/examples/pktdump

use crate::dpdk2::LcoreId;
use clap::{clap_app, crate_version};
use failure::Fallible;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::fs;

/// Runtime configuration settings.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Application name. This must be unique if you want to run multiple
    /// DPDK applications on the same system.
    pub app_name: String,

    /// Indicating whether the process is a secondary process. Secondary
    /// process cannot initialize shared memory, but can attach to pre-
    /// initialized shared memory by the primary process and create objects
    /// in it. Defaults to `false`.
    #[serde(default)]
    pub secondary: bool,

    /// Application group name. Use this to group primary and secondary
    /// processes together in a multi-process setup; and allow them to share
    /// the same memory regions. The default value is the `app_name`. Each
    /// process works independently.
    #[serde(default)]
    pub app_group: Option<String>,

    /// The identifier of the main core. This is the core the main thread
    /// will run on.
    pub main_core: LcoreId,

    /// Additional cores that are available to the application, and can be
    /// used for running general tasks. Packet pipelines cannot be run on
    /// these cores unless the core is also assigned to a port separately.
    /// Defaults to empty list.
    pub cores: Vec<LcoreId>,

    /// Per mempool settings. On a system with multiple sockets, aka NUMA
    /// nodes, one mempool will be allocated for each socket the apllication
    /// uses.
    #[serde(default)]
    pub mempool: MempoolConfig,

    /// The ports to use for the application. Must have at least one.
    pub ports: Vec<PortConfig>,

    /// Additional DPDK [`parameters`] to pass on for EAL initialization. When
    /// set, the values are passed through as is without validation.
    ///
    /// [`parameters`]: https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
    #[serde(default)]
    pub dpdk_args: Option<String>,
}

impl RuntimeConfig {
    fn other_cores(&self) -> Vec<LcoreId> {
        let mut cores = vec![];
        cores.extend(self.cores.iter());

        self.ports.iter().for_each(|port| {
            if let Some(rx_core) = port.rx_core {
                cores.push(rx_core);
            }
            if let Some(tx_core) = port.tx_core {
                cores.push(tx_core);
            }
        });

        cores.sort();
        cores.dedup();
        cores
    }

    /// Extracts the EAL arguments from runtime settings.
    pub(crate) fn to_eal_args(&self) -> Vec<String> {
        let mut eal_args = vec![];

        // adds the app name.
        eal_args.push(self.app_name.clone());

        // adds the proc type.
        let proc_type = if self.secondary {
            "secondary"
        } else {
            "primary"
        };
        eal_args.push("--proc-type".to_owned());
        eal_args.push(proc_type.to_owned());

        // adds the mem file prefix.
        let prefix = self.app_group.as_ref().unwrap_or(&self.app_name);
        eal_args.push("--file-prefix".to_owned());
        eal_args.push(prefix.clone());

        // adds all the ports.
        let pcie = Regex::new(r"^\d{4}:\d{2}:\d{2}\.\d$").unwrap();
        self.ports.iter().for_each(|port| {
            if pcie.is_match(port.device.as_str()) {
                eal_args.push("--pci-whitelist".to_owned());
                eal_args.push(port.device.clone());
            } else {
                let vdev = if let Some(args) = &port.args {
                    format!("{},{}", port.device, args)
                } else {
                    port.device.clone()
                };
                eal_args.push("--vdev".to_owned());
                eal_args.push(vdev);
            }
        });

        let mut main = self.main_core;
        let others = self.other_cores();

        // if the main lcore is also used for other tasks, we will assign
        // another lcore to be the main, and set the affinity to the same
        // physical core/cpu. this is necessary because we need to be able
        // to run an executor for other tasks without blocking the main
        // application thread.
        if others.contains(&main) {
            main = LcoreId::LAST;
        }

        // adds the main core.
        eal_args.push("--master-lcore".to_owned());
        eal_args.push(main.raw().to_string());

        // adds all the lcores.
        let mut cores = others
            .into_iter()
            .map(|lcore| lcore.raw().to_string())
            .collect::<Vec<_>>()
            .join(",");
        cores.push_str(&format!(",{}@{}", main.raw(), self.main_core.raw()));
        eal_args.push("--lcores".to_owned());
        eal_args.push(cores);

        // adds additional DPDK args.
        if let Some(args) = &self.dpdk_args {
            eal_args.extend(args.split_ascii_whitespace().map(str::to_owned));
        }

        eal_args
    }
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("RuntimeConfig");
        d.field("app_name", &self.app_name)
            .field("secondary", &self.secondary)
            .field(
                "app_group",
                self.app_group.as_ref().unwrap_or(&self.app_name),
            )
            .field("main_core", &self.main_core)
            .field("cores", &self.cores)
            .field("mempool", &self.mempool)
            .field("ports", &self.ports);
        if let Some(dpdk_args) = &self.dpdk_args {
            d.field("dpdk_args", dpdk_args);
        }
        d.finish()
    }
}

/// Mempool configuration settings.
#[derive(Clone, Deserialize)]
pub struct MempoolConfig {
    /// The maximum number of Mbufs the mempool can allocate. The optimum
    /// size (in terms of memory usage) is when n is a power of two minus
    /// one. Defaults to `65535` or `2 ^ 16 - 1`.
    #[serde(default = "default_capacity")]
    pub capacity: usize,

    /// The size of the per core object cache. If cache_size is non-zero,
    /// the library will try to limit the accesses to the common lockless
    /// pool. The cache can be disabled if the argument is set to 0. Defaults
    /// to `0`.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_capacity() -> usize {
    65535
}

fn default_cache_size() -> usize {
    0
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            capacity: default_capacity(),
            cache_size: default_cache_size(),
        }
    }
}

impl fmt::Debug for MempoolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MempoolConfig")
            .field("capacity", &self.capacity)
            .field("cache_size", &self.cache_size)
            .finish()
    }
}

/// Port configuration settings.
#[derive(Clone, Deserialize)]
pub struct PortConfig {
    /// The application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub name: String,

    /// The device name of the port. It can be the following formats,
    ///
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    pub device: String,

    /// Additional arguments to configure a virtual device.
    #[serde(default)]
    pub args: Option<String>,

    /// The lcore to receive packets on.
    #[serde(default)]
    pub rx_core: Option<LcoreId>,

    /// The lcore to transmit packets on.
    #[serde(default)]
    pub tx_core: Option<LcoreId>,

    /// The receive queue capacity. Defaults to `128`.
    #[serde(default = "default_port_rxq_capacity")]
    pub rxq_capacity: usize,

    /// The transmit queue capacity. Defaults to `128`.
    #[serde(default = "default_port_txq_capacity")]
    pub txq_capacity: usize,

    /// Whether promiscuous mode is enabled for this port. Defaults to `true`.
    #[serde(default = "default_promiscuous_mode")]
    pub promiscuous: bool,

    /// Whether multicast packet reception is enabled for this port. Defaults
    /// to `true`.
    #[serde(default = "default_multicast_mode")]
    pub multicast: bool,
}

fn default_port_rxq_capacity() -> usize {
    128
}

fn default_port_txq_capacity() -> usize {
    128
}

fn default_promiscuous_mode() -> bool {
    true
}

fn default_multicast_mode() -> bool {
    true
}

impl fmt::Debug for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("PortConfig");
        d.field("name", &self.name);
        d.field("device", &self.device);
        if let Some(args) = &self.args {
            d.field("args", args);
        }
        if let Some(rx_core) = &self.rx_core {
            d.field("rx_core", rx_core);
        }
        if let Some(tx_core) = &self.tx_core {
            d.field("tx_core", tx_core);
        }
        d.field("rxq_capacity", &self.rxq_capacity)
            .field("txq_capacity", &self.txq_capacity)
            .field("promiscuous", &self.promiscuous)
            .field("multicast", &self.multicast)
            .finish()
    }
}

/// Loads the app config from a TOML file.
///
/// # Example
///
/// ```
/// home$ ./myapp -f config.toml
/// ```
pub fn load_config() -> Fallible<RuntimeConfig> {
    let matches = clap_app!(capsule =>
        (version: crate_version!())
        (@arg file: -f --file +required +takes_value "configuration file")
    )
    .get_matches();

    let path = matches.value_of("file").unwrap();
    let content = fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|err| err.into())
}

// make `LcoreId` serde deserializable.
impl<'de> Deserialize<'de> for LcoreId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let i = u32::deserialize(deserializer)?;
        Ok(LcoreId(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        const CONFIG: &str = r#"
            app_name = "myapp"
            main_core = 0
            cores = [1, 2]

            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG).unwrap();

        assert_eq!(false, config.secondary);
        assert_eq!(None, config.app_group);
        assert_eq!(None, config.dpdk_args);
        assert_eq!(default_capacity(), config.mempool.capacity);
        assert_eq!(default_cache_size(), config.mempool.cache_size);
        assert_eq!(None, config.ports[0].args);
        assert_eq!(None, config.ports[0].rx_core);
        assert_eq!(None, config.ports[0].tx_core);
        assert_eq!(default_port_rxq_capacity(), config.ports[0].rxq_capacity);
        assert_eq!(default_port_txq_capacity(), config.ports[0].txq_capacity);
        assert_eq!(default_promiscuous_mode(), config.ports[0].promiscuous);
        assert_eq!(default_multicast_mode(), config.ports[0].multicast);
    }

    #[test]
    fn config_to_eal_args() {
        const CONFIG: &str = r#"
            app_name = "myapp"
            secondary = false
            app_group = "mygroup"
            main_core = 0
            cores = [1, 2]
            dpdk_args = "-v --log-level eal:8"

            [mempool]
                capacity = 255
                cache_size = 16

            [[ports]]
                name = "eth0"
                device = "0000:00:01.0"
                rx_core = 3
                rxq_capacity = 32
                tx_core = 0
                txq_capacity = 32

            [[ports]]
                name = "eth1"
                device = "net_pcap0"
                args = "rx=lo,tx=lo"
                rxq_capacity = 32
                tx_core = 4
                txq_capacity = 32
        "#;

        let config: RuntimeConfig = toml::from_str(CONFIG).unwrap();

        assert_eq!(
            &[
                "myapp",
                "--proc-type",
                "primary",
                "--file-prefix",
                "mygroup",
                "--pci-whitelist",
                "0000:00:01.0",
                "--vdev",
                "net_pcap0,rx=lo,tx=lo",
                "--master-lcore",
                "127",
                "--lcores",
                "0,1,2,3,4,127@0",
                "-v",
                "--log-level",
                "eal:8"
            ],
            config.to_eal_args().as_slice(),
        )
    }
}
