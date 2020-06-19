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

use super::{LcoreId, Mbuf, Mempool, SocketId, ToDpdkResult};
use crate::ffi::{self, ToCString};
use crate::net::MacAddr;
use crate::{debug, ensure, info, warn};
use failure::{Fail, Fallible};
use std::fmt;
use std::os::raw;
use std::ptr;

/// An opaque identifier for a PMD device port.
#[derive(Copy, Clone)]
pub(crate) struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    #[inline]
    pub(crate) fn socket(self) -> SocketId {
        unsafe { SocketId(ffi::rte_eth_dev_socket_id(self.0) as raw::c_int) }
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

/// A receive queue index.
#[derive(Copy, Clone)]
struct RxQueueIndex(u16);

impl RxQueueIndex {
    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

/// A receive queue.
pub(crate) struct PortRxQueue {
    port: PortId,
    index: RxQueueIndex,
    // hack to make the type !Send and !Sync
    #[cfg(not(feature = "negative_impls"))]
    _phantom: std::marker::PhantomData<*const ()>,
}

impl PortRxQueue {
    fn new(port: PortId, index: RxQueueIndex) -> PortRxQueue {
        PortRxQueue {
            port,
            index,
            #[cfg(not(feature = "negative_impls"))]
            _phantom: Default::default(),
        }
    }

    /// Receives a burst of Mbufs to fill the packets buffer.
    pub(crate) fn receive(&self, packets: &mut Vec<Mbuf>) {
        let max = packets.capacity();

        unsafe {
            let len = ffi::_rte_eth_rx_burst(
                self.port.raw(),
                self.index.raw(),
                // `Mbuf` has the same layout as `*mut rte_mbuf`, it's safe to
                // perform a pointer conversion here.
                packets.as_mut_ptr() as *mut *mut ffi::rte_mbuf,
                max as u16,
            );
            packets.set_len(len as usize);
        }
    }
}

impl fmt::Debug for PortRxQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortRxQueue")
            .field("port", &self.port)
            .field("index", &self.index.raw())
            .finish()
    }
}

#[cfg(feature = "negative_impls")]
impl !Send for PortRxQueue {}

#[cfg(feature = "negative_impls")]
impl !Sync for PortRxQueue {}

/// A transmit queue index.
#[derive(Copy, Clone)]
struct TxQueueIndex(u16);

impl TxQueueIndex {
    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

/// A transmit queue.
pub(crate) struct PortTxQueue {
    port: PortId,
    index: TxQueueIndex,
    // hack to make the type !Send and !Sync
    #[cfg(not(feature = "negative_impls"))]
    _phantom: std::marker::PhantomData<*const ()>,
}

impl PortTxQueue {
    fn new(port: PortId, index: TxQueueIndex) -> PortTxQueue {
        PortTxQueue {
            port,
            index,
            #[cfg(not(feature = "negative_impls"))]
            _phantom: Default::default(),
        }
    }

    /// Transmits the packets in the buffer.
    pub(crate) fn transmit(&self, packets: &mut Vec<Mbuf>) {
        let mut to_send = packets.len();
        let mut ptrs = packets.as_mut_ptr() as *mut *mut ffi::rte_mbuf;

        loop {
            let sent = unsafe {
                ffi::_rte_eth_tx_burst(self.port.raw(), self.index.raw(), ptrs, to_send as u16)
                    as usize
            };

            to_send -= sent;
            if sent > 0 && to_send > 0 {
                // still have packets not sent. tx queue is full but still making
                // progress. we will keep trying until all packets are sent.
                ptrs = unsafe { ptrs.add(sent) };
            } else {
                break;
            }
        }

        if to_send > 0 {
            // tx queue is full and we can't make progress, start dropping packets
            // to avoid potentially stuck in an endless loop.
            let start = packets.len() - to_send;
            let drops = packets.drain(start..);
            Mbuf::free_bulk(drops);
        }

        unsafe {
            // ownership of the packets are given to `rte_eth_tx_burst`, we will
            // mark the packets buffer empty.
            packets.set_len(0);
        }
    }
}

impl fmt::Debug for PortTxQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortTxQueue")
            .field("port", &self.port)
            .field("index", &self.index.raw())
            .finish()
    }
}

#[cfg(feature = "negative_impls")]
impl !Send for PortTxQueue {}

#[cfg(feature = "negative_impls")]
impl !Sync for PortTxQueue {}

/// Port related errors.
#[derive(Debug, Fail)]
pub(crate) enum PortError {
    /// The RX or TX queue for an lcore is not bound.
    #[fail(display = "Port RX or TX queue for {:?} not found.", _0)]
    QueueNotFound(LcoreId),

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
    rx_lcores: Vec<LcoreId>,
    tx_lcores: Vec<LcoreId>,
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
            // see `promiscuous` comments.
            _ => false,
        }
    }

    /// Returns the RX queue for the current lcore.
    pub(crate) fn get_rxq(&self) -> Fallible<PortRxQueue> {
        let lcore = LcoreId::current();
        match self.rx_lcores.iter().position(|&x| x == lcore) {
            Some(index) => Ok(PortRxQueue::new(self.port_id, RxQueueIndex(index as u16))),
            None => Err(PortError::QueueNotFound(lcore).into()),
        }
    }

    /// Returns the TX queue for the current lcore.
    pub(crate) fn get_txq(&self) -> Fallible<PortTxQueue> {
        let lcore = LcoreId::current();
        match self.tx_lcores.iter().position(|&x| x == lcore) {
            Some(index) => Ok(PortTxQueue::new(self.port_id, TxQueueIndex(index as u16))),
            None => Err(PortError::QueueNotFound(lcore).into()),
        }
    }

    /// Starts the port. This is the final step before packets can be
    /// received or transmitted on this port.
    ///
    /// # Errors
    ///
    /// If the port fails to start, `DpdkError` is returned.
    pub(crate) fn start(&self) -> Fallible<()> {
        unsafe {
            ffi::rte_eth_dev_start(self.port_id.raw()).to_dpdk_result()?;
        }

        info!(port = ?self.name, "port started.");
        Ok(())
    }

    /// Stops the port.
    pub(crate) fn stop(&self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.port_id.raw());
        }

        info!(port = ?self.name, "port stopped.");
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
            .field("rx_lcores", &self.rx_lcores)
            .field("tx_lcores", &self.tx_lcores)
            .field("promiscuous", &self.promiscuous())
            .field("multicast", &self.multicast())
            .finish()
    }
}

/// Configures a PMD port from the configuration values.
pub(crate) struct PortBuilder {
    name: String,
    port_id: PortId,
    rx_lcores: Vec<LcoreId>,
    tx_lcores: Vec<LcoreId>,
    rxq_capacity: u16,
    txq_capacity: u16,
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
            rx_lcores: vec![],
            tx_lcores: vec![],
            rxq_capacity: info.rx_desc_lim.nb_min,
            txq_capacity: info.tx_desc_lim.nb_min,
            info,
            conf: ffi::rte_eth_conf::default(),
        })
    }

    /// Sets the lcores to receive packets on.
    ///
    /// If more than one lcore is used, also enables receive side scaling.
    pub(crate) fn set_rx_lcores(&mut self, lcores: Vec<LcoreId>) -> Fallible<&mut Self> {
        ensure!(
            !lcores.is_empty() && self.info.max_rx_queues >= lcores.len() as u16,
            PortError::InsufficientRxQueues(self.info.max_rx_queues as usize)
        );

        if lcores.len() > 1 {
            const RSS_HF: u64 =
                (ffi::ETH_RSS_IP | ffi::ETH_RSS_TCP | ffi::ETH_RSS_UDP | ffi::ETH_RSS_SCTP) as u64;

            // enables receive side scaling.
            self.conf.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            self.conf.rx_adv_conf.rss_conf.rss_hf = self.info.flow_type_rss_offloads & RSS_HF;

            debug!(port = ?self.name, rss_hf = self.conf.rx_adv_conf.rss_conf.rss_hf, "receive side scaling enabled.");
        }

        self.rx_lcores = lcores;
        Ok(self)
    }

    /// Sets the lcores to transmit packets on.
    pub(crate) fn set_tx_lcores(&mut self, lcores: Vec<LcoreId>) -> Fallible<&mut Self> {
        ensure!(
            !lcores.is_empty() && self.info.max_tx_queues >= lcores.len() as u16,
            PortError::InsufficientTxQueues(self.info.max_tx_queues as usize)
        );

        self.tx_lcores = lcores;
        Ok(self)
    }

    /// Sets the capacity of each RX queue and TX queue.
    ///
    /// If the sizes are not within the limits of the device, they are adjusted
    /// to the boundaries.
    pub(crate) fn set_rxq_txq_capacity(&mut self, rx: usize, tx: usize) -> Fallible<&mut Self> {
        let mut rxq_capacity = rx as u16;
        let mut txq_capacity = tx as u16;

        unsafe {
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(
                self.port_id.raw(),
                &mut rxq_capacity,
                &mut txq_capacity,
            )
            .to_dpdk_result()?;
        }

        info!(
            cond: rxq_capacity != rx as u16,
            port = ?self.name,
            before = rx,
            after = rxq_capacity,
            "rx ring size adjusted to limits.",
        );
        info!(
            cond: txq_capacity != tx as u16,
            port = ?self.name,
            before = tx,
            after = txq_capacity,
            "tx ring size adjusted to limits.",
        );

        self.rxq_capacity = rxq_capacity;
        self.txq_capacity = txq_capacity;
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
                ffi::rte_eth_promiscuous_enable(self.port_id.raw()).to_dpdk_result()?;
                debug!(port = ?self.name, "promiscuous mode enabled.");
            } else {
                ffi::rte_eth_promiscuous_disable(self.port_id.raw()).to_dpdk_result()?;
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
                ffi::rte_eth_allmulticast_enable(self.port_id.raw()).to_dpdk_result()?;
                debug!(port = ?self.name, "multicast mode enabled.");
            } else {
                ffi::rte_eth_allmulticast_disable(self.port_id.raw()).to_dpdk_result()?;
                debug!(port = ?self.name, "multicast mode disabled.");
            }
        }

        Ok(self)
    }

    /// Finishes initializing the PMD port.
    pub(crate) fn finish(&mut self, mempool: &mut Mempool) -> Fallible<Port> {
        // turns on optimization for mbuf fast free.
        if self.info.tx_offload_capa & ffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64 > 0 {
            self.conf.txmode.offloads |= ffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            debug!(port = ?self.name, "mbuf fast free enabled.");
        }

        // configures the device before everything else.
        unsafe {
            ffi::rte_eth_dev_configure(
                self.port_id.raw(),
                self.rx_lcores.len() as u16,
                self.tx_lcores.len() as u16,
                &self.conf,
            )
            .to_dpdk_result()?;
        }

        let socket = self.port_id.socket();
        warn!(
            cond: mempool.socket() != socket,
            message = "mempool socket does not match port socket.",
            mempool = ?mempool.socket(),
            port = ?socket
        );

        // configures the rx queues.
        for rxq_idx in 0..self.rx_lcores.len() {
            unsafe {
                ffi::rte_eth_rx_queue_setup(
                    self.port_id.raw(),
                    rxq_idx as u16,
                    self.rxq_capacity,
                    socket.raw() as raw::c_uint,
                    ptr::null(),
                    mempool.raw_mut(),
                )
                .to_dpdk_result()?;
            }
        }

        // configures the tx queues.
        for txq_idx in 0..self.tx_lcores.len() {
            unsafe {
                ffi::rte_eth_tx_queue_setup(
                    self.port_id.raw(),
                    txq_idx as u16,
                    self.txq_capacity,
                    socket.raw() as raw::c_uint,
                    ptr::null(),
                )
                .to_dpdk_result()?;
            }
        }

        Ok(Port {
            name: self.name.clone(),
            port_id: self.port_id,
            rx_lcores: self.rx_lcores.clone(),
            tx_lcores: self.tx_lcores.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsule::dpdk2;
    use std::sync::Arc;

    #[capsule::test]
    fn get_port_socket() {
        assert_eq!(SocketId(0), PortId(0).socket());
    }

    #[capsule::test]
    fn port_not_found() {
        assert!(PortBuilder::new("test0", "notfound").is_err());
    }

    #[capsule::test]
    fn set_rx_lcores() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // ring port has a max rxq of 16.
        let lcores = (0..17).map(LcoreId).collect::<Vec<_>>();
        assert!(builder.set_rx_lcores(lcores).is_err());

        let lcores = (0..16).map(LcoreId).collect::<Vec<_>>();
        assert!(builder.set_rx_lcores(lcores.clone()).is_ok());
        assert_eq!(lcores, builder.rx_lcores);

        Ok(())
    }

    #[capsule::test]
    fn set_tx_lcores() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // ring port has a max txq of 16.
        let lcores = (0..17).map(LcoreId).collect::<Vec<_>>();
        assert!(builder.set_tx_lcores(lcores).is_err());

        let lcores = (0..16).map(LcoreId).collect::<Vec<_>>();
        assert!(builder.set_tx_lcores(lcores.clone()).is_ok());
        assert_eq!(lcores, builder.tx_lcores);

        Ok(())
    }

    #[capsule::test]
    fn set_rxq_txq_capacity() -> Fallible<()> {
        let mut builder = PortBuilder::new("test0", "net_ring0")?;

        // unfortunately can't test boundary adjustment
        assert!(builder.set_rxq_txq_capacity(32, 32).is_ok());
        assert_eq!(32, builder.rxq_capacity);
        assert_eq!(32, builder.txq_capacity);

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
    fn build_port() -> Fallible<()> {
        let rx_lcores = (0..2).map(LcoreId).collect::<Vec<_>>();
        let tx_lcores = (3..6).map(LcoreId).collect::<Vec<_>>();
        let mut pool = Mempool::new("mp_build_port", 15, 0, SocketId::ANY)?;
        let port = PortBuilder::new("test0", "net_ring0")?
            .set_rx_lcores(rx_lcores.clone())?
            .set_tx_lcores(tx_lcores.clone())?
            .finish(&mut pool)?;

        assert_eq!("test0", port.name());
        assert!(port.promiscuous());
        assert!(port.multicast());
        assert_eq!(rx_lcores, port.rx_lcores);
        assert_eq!(tx_lcores, port.tx_lcores);

        Ok(())
    }

    #[capsule::test]
    fn rxq_not_found() -> Fallible<()> {
        let mut pool = Mempool::new("mp_rxq_not_found", 15, 0, SocketId::ANY)?;
        let port = PortBuilder::new("test0", "net_ring0")?
            .set_rx_lcores(vec![LcoreId(1)])?
            .finish(&mut pool)?;

        assert!(port.get_rxq().is_err());

        Ok(())
    }

    #[capsule::test]
    fn txq_not_found() -> Fallible<()> {
        let mut pool = Mempool::new("mp_txq_not_found", 15, 0, SocketId::ANY)?;
        let port = PortBuilder::new("test0", "net_ring0")?
            .set_tx_lcores(vec![LcoreId(1)])?
            .finish(&mut pool)?;

        assert!(port.get_txq().is_err());

        Ok(())
    }

    #[capsule::test]
    fn port_rx_tx() -> Fallible<()> {
        let lcore = LcoreId(1);
        let mut pool = Mempool::new("mp_port_rx_tx", 15, 0, SocketId::ANY)?;
        let port = PortBuilder::new("test0", "net_null0")?
            .set_rx_lcores(vec![lcore])?
            .set_tx_lcores(vec![lcore])?
            .finish(&mut pool)?;
        let port = Arc::new(port);

        port.start()?;

        let handle = port.clone();
        dpdk2::spawn(lcore, move || {
            let rxq = handle.get_rxq().unwrap();
            let txq = handle.get_txq().unwrap();

            let mut packets = Vec::with_capacity(4);
            assert_eq!(0, packets.len());

            rxq.receive(&mut packets);
            assert_eq!(4, packets.len());

            txq.transmit(&mut packets);
            assert_eq!(0, packets.len());
        })?
        .join()
        .expect("panic!");

        port.stop();
        Ok(())
    }
}
