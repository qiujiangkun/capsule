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

use super::{SocketId, ToDpdkResult};
use crate::ffi::{self, ToCString};
use crate::net::MacAddr;
use crate::{debug, ensure, info};
use failure::{Fail, Fallible};
use std::fmt;
use std::os::raw;

/// An opaque identifier for a PMD device port.
#[derive(Copy, Clone)]
pub(crate) struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    ///
    /// Virtual devices do not have real socket IDs. The value returned
    /// will be discarded if it does not match any of the system's physical
    /// socket IDs.
    #[inline]
    pub(crate) fn socket_id(self) -> Option<SocketId> {
        unsafe { ffi::rte_eth_dev_socket_id(self.0) }
            .to_dpdk_result()
            .ok()
            .and_then(|id| {
                let id = SocketId(id as raw::c_int);
                if SocketId::all().contains(&id) {
                    Some(id)
                } else {
                    None
                }
            })
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "port{}", self.0)
    }
}

/// Port related errors.
#[derive(Debug, Fail)]
pub(crate) enum PortError {
    /// The maximum number of RX queues is less than the number of queues
    /// requested.
    #[fail(display = "Insufficient number of RX queues. Max is {}.", _0)]
    InsufficientRxQueues(usize),

    /// The maximum number of TX queues is less than the number of queues
    /// requested.
    #[fail(display = "Insufficient number of TX queues. Max is {}.", _0)]
    InsufficientTxQueues(usize),
}

/// A PMD device port.
pub(crate) struct Port {
    name: String,
    port_id: PortId,
}

impl Port {
    /// Returns the application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Returns the port ID.
    pub(crate) fn port_id(&self) -> PortId {
        self.port_id
    }

    /// Returns the MAC address of the port.
    pub(crate) fn mac_addr(&self) -> MacAddr {
        super::eth_macaddr_get(self.port_id.0).unwrap_or_default()
    }

    /// Returns whether the port has promiscuous mode enabled.
    pub(crate) fn promiscuous(&self) -> bool {
        match unsafe { ffi::rte_eth_promiscuous_get(self.port_id.raw()).to_dpdk_result() } {
            Ok(1) => true,
            // since `port_id` is guaranteed to be valid, should never fail.
            // but just in case, we treat error as mode disabled.
            _ => false,
        }
    }

    /// Returns whether the port has multicast mode enabled.
    pub(crate) fn multicast(&self) -> bool {
        match unsafe { ffi::rte_eth_allmulticast_get(self.port_id.raw()).to_dpdk_result() } {
            Ok(1) => true,
            // see `promiscuous` for comment.
            _ => false,
        }
    }

    /// Stops and closes the port.
    ///
    /// The port cannot be restarted! Should only be invoked on application
    /// termination.
    pub(crate) fn close(self) {
        unsafe {
            ffi::rte_eth_dev_close(self.port_id.raw());
        }

        debug!(port = ?self.name(), "port closed.");
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("name", &self.name())
            .field("port_id", &self.port_id())
            .field("mac_addr", &format_args!("{}", self.mac_addr()))
            .field("promiscuous", &self.promiscuous())
            .field("multicast", &self.multicast())
            .finish()
    }
}

/// Configures a PMD port from the configuration values.
pub(crate) struct PortBuilder {
    name: String,
    port_id: PortId,
    rxq_count: u16,
    rxq_size: u16,
    txq_count: u16,
    txq_size: u16,
    info: ffi::rte_eth_dev_info,
    conf: ffi::rte_eth_conf,
}

impl PortBuilder {
    /// Creates a new `PortBuilder` with a logical name and device name.
    ///
    /// The device name can be the following
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// Returns an error if the `device` is not found.
    pub(crate) fn new<S1: Into<String>, S2: Into<String>>(name: S1, device: S2) -> Fallible<Self> {
        let name: String = name.into();
        let device: String = device.into();
        let mut port_id = 0u16;

        unsafe {
            ffi::rte_eth_dev_get_port_by_name(device.clone().to_cstring().as_ptr(), &mut port_id)
                .to_dpdk_result()?;
        }

        let port_id = PortId(port_id);
        debug!(port = ?name, "{:?} is {}.", port_id, device);

        let mut info = ffi::rte_eth_dev_info::default();
        unsafe {
            ffi::rte_eth_dev_info_get(port_id.raw(), &mut info).to_dpdk_result()?;
        }

        Ok(PortBuilder {
            name,
            port_id,
            rxq_count: 1,
            rxq_size: info.rx_desc_lim.nb_min,
            txq_count: 1,
            txq_size: info.tx_desc_lim.nb_min,
            info,
            conf: ffi::rte_eth_conf::default(),
        })
    }

    /// Sets the number of receiving queues for the port.
    pub(crate) fn set_rxq_count(&mut self, count: u16) -> Fallible<&mut Self> {
        ensure!(
            count > 0 && self.info.max_rx_queues >= count,
            PortError::InsufficientRxQueues(self.info.max_rx_queues as usize)
        );

        if count > 1 {
            const RSS_HF: u64 =
                (ffi::ETH_RSS_IP | ffi::ETH_RSS_TCP | ffi::ETH_RSS_UDP | ffi::ETH_RSS_SCTP) as u64;

            // enables receive side scaling.
            self.conf.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            self.conf.rx_adv_conf.rss_conf.rss_hf = self.info.flow_type_rss_offloads & RSS_HF;

            debug!(port = ?self.name, rss_hf = self.conf.rx_adv_conf.rss_conf.rss_hf, "receive side scaling enabled.");
        }

        self.rxq_count = count;
        Ok(self)
    }

    /// Sets the number of transmit queues for the port.
    pub(crate) fn set_txq_count(&mut self, count: u16) -> Fallible<&mut Self> {
        ensure!(
            count > 0 && self.info.max_tx_queues >= count,
            PortError::InsufficientTxQueues(self.info.max_tx_queues as usize)
        );

        self.txq_count = count;
        Ok(self)
    }

    /// Sets the ring size of each RX queue and TX queue.
    ///
    /// If the sizes are not within the limits of the device, they are adjusted
    /// to the boundaries.
    pub(crate) fn set_rx_tx_ring_size(&mut self, rx: u16, tx: u16) -> Fallible<&mut Self> {
        let mut rxq_size = rx;
        let mut txq_size = tx;

        unsafe {
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(self.port_id.0, &mut rxq_size, &mut txq_size)
                .to_dpdk_result()?;
        }

        info!(
            cond: rxq_size != rx,
            message = "rx ring size adjusted to limits.",
            before = rx,
            after = rxq_size
        );
        info!(
            cond: txq_size != tx,
            message = "tx ring size adjusted to limits.",
            before = tx,
            after = txq_size
        );

        self.rxq_size = rxq_size;
        self.txq_size = txq_size;
        Ok(self)
    }

    /// Sets the promiscuous mode of the port.
    ///
    /// # Errors
    ///
    /// Returns an error if the device does not support configurable mode.
    pub(crate) fn set_promiscuous(&mut self, enable: bool) -> Fallible<&mut Self> {
        unsafe {
            if enable {
                ffi::rte_eth_promiscuous_enable(self.port_id.0).to_dpdk_result()?;
                debug!(port = ?self.name, "promiscuous mode enabled.");
            } else {
                ffi::rte_eth_promiscuous_disable(self.port_id.0).to_dpdk_result()?;
                debug!(port = ?self.name, "promiscuous mode disabled.");
            }
        }

        Ok(self)
    }

    /// Sets the multicast mode of the port.
    ///
    /// # Errors
    ///
    /// Returns an error if the device does not support configurable mode.
    pub(crate) fn set_multicast(&mut self, enable: bool) -> Fallible<&mut Self> {
        unsafe {
            if enable {
                ffi::rte_eth_allmulticast_enable(self.port_id.0).to_dpdk_result()?;
                debug!(port = ?self.name, "multicast mode enabled.");
            } else {
                ffi::rte_eth_allmulticast_disable(self.port_id.0).to_dpdk_result()?;
                debug!(port = ?self.name, "multicast mode disabled.");
            }
        }

        Ok(self)
    }

    /// Returns the PMD port.
    pub(crate) fn finish(&mut self) -> Fallible<Port> {
        Ok(Port {
            name: self.name.clone(),
            port_id: self.port_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[capsule::test]
    fn port_not_found() {
        assert!(PortBuilder::new("test0", "notfound").is_err());
    }

    #[capsule::test]
    fn set_rxq_count() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // ring port has a max rxq of 16.
        assert!(builder.set_rxq_count(32).is_err());

        assert!(builder.set_rxq_count(8).is_ok());
        assert_eq!(8, builder.rxq_count);

        Ok(())
    }

    #[capsule::test]
    fn set_txq_count() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // ring port has a max txq of 16.
        assert!(builder.set_txq_count(32).is_err());

        assert!(builder.set_txq_count(8).is_ok());
        assert_eq!(8, builder.txq_count);

        Ok(())
    }

    #[capsule::test]
    fn set_rx_tx_ring_size() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // unfortunately can't test boundary adjustment with the vdevs
        assert!(builder.set_rx_tx_ring_size(32, 32).is_ok());
        assert_eq!(32, builder.rxq_size);
        assert_eq!(32, builder.txq_size);

        Ok(())
    }

    #[capsule::test]
    fn set_promiscuous() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_tap0")?;

        assert!(builder.set_promiscuous(true).is_ok());
        assert!(builder.set_promiscuous(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn set_multicast() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_tap0")?;

        assert!(builder.set_multicast(true).is_ok());
        assert!(builder.set_multicast(false).is_ok());

        Ok(())
    }

    #[capsule::test]
    fn create_port() -> Fallible<()> {
        let port = PortBuilder::new("test0", "net_null0")?.finish()?;

        assert_eq!("test0", port.name());
        assert!(port.promiscuous());
        assert!(port.multicast());

        Ok(())
    }
}
