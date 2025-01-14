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

use super::CoreId;
use super::Kni;
use super::KniBuilder;
use super::KniTxQueue;
use super::Mbuf;
use super::Mempool;
use super::MempoolMap;
use super::SocketId;
use crate::debug;
use crate::dpdk::DpdkError;
use crate::ensure;
use crate::ffi::AsStr;
use crate::ffi::ToCString;
use crate::ffi::ToResult;
use crate::ffi::{self};
use crate::info;
use crate::net::MacAddr;
#[cfg(feature = "pcap-dump")]
use crate::pcap;
use crate::warn;
use anyhow::Result;
use std::collections::HashMap;
use std::fmt;
use std::mem::MaybeUninit;
use std::os::raw;
use std::ptr;
use thiserror::Error;

const DEFAULT_RSS_HF: u64 = (ffi::ETH_RSS_IP | ffi::ETH_RSS_TCP | ffi::ETH_RSS_UDP | ffi::ETH_RSS_SCTP) as u64;

/// An opaque identifier for an Ethernet device port.
#[derive(Copy, Clone)]
pub struct PortId(u16);

impl PortId {
    /// Returns the ID of the socket the port is connected to.
    ///
    /// Virtual devices do not have real socket IDs. The value returned
    /// will be discarded if it does not match any of the system's physical
    /// socket IDs.
    #[inline]
    pub fn socket_id(self) -> Option<SocketId> {
        let id = unsafe { SocketId(ffi::rte_eth_dev_socket_id(self.0)) };
        if SocketId::all().contains(&id) {
            Some(id)
        } else {
            None
        }
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub fn raw(&self) -> u16 { self.0 }
}

impl fmt::Debug for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "port{}", self.0) }
}

/// The index of a receive queue.
#[derive(Copy, Clone)]
pub struct RxQueueIndex(u16);

impl RxQueueIndex {
    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref, dead_code)]
    #[inline]
    pub fn raw(&self) -> u16 { self.0 }
}

/// The index of a transmit queue.
#[derive(Copy, Clone)]
pub struct TxQueueIndex(u16);

impl TxQueueIndex {
    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref, dead_code)]
    #[inline]
    pub fn raw(&self) -> u16 { self.0 }
}

/// Either queue type (receive or transmit) with associated index.
#[allow(dead_code)]
pub enum RxTxQueue {
    Rx(RxQueueIndex),
    Tx(TxQueueIndex),
}

/// The receive and transmit queue abstraction. Instead of modeling them
/// as two standalone queues, in the run-to-completion mode, they are modeled
/// as a queue pair associated with the core that runs the pipeline from
/// receive to send.
#[allow(missing_debug_implementations)]
pub struct PortQueue {
    port_id: PortId,
    rxq: RxQueueIndex,
    txq: TxQueueIndex,
    kni: Option<KniTxQueue>,
    received_bufs: Vec<MaybeUninit<Mbuf>>,
    received_bufs_ptr: Vec<*mut ffi::rte_mbuf>,
    received_index_l: usize,
    received_index_h: usize,
}

impl Clone for PortQueue {
    fn clone(&self) -> Self {
        Self {
            port_id: self.port_id.clone(),
            rxq: self.rxq.clone(),
            txq: self.txq.clone(),
            kni: self.kni.clone(),
            #[cfg(feature = "metrics")]
            received: self.received.clone(),
            #[cfg(feature = "metrics")]
            transmitted: self.transmitted.clone(),
            #[cfg(feature = "metrics")]
            dropped: self.dropped.clone(),
            received_bufs: (0..Self::RX_BURST_MAX).map(|_| MaybeUninit::uninit()).collect(),
            received_bufs_ptr: vec![ptr::null_mut(); Self::RX_BURST_MAX],
            received_index_l: 0,
            received_index_h: 0,
        }
    }
}

impl PortQueue {
    const RX_BURST_MAX: usize = 32;

    fn new(port: PortId, rxq: RxQueueIndex, txq: TxQueueIndex) -> Self {
        PortQueue {
            port_id: port,
            rxq,
            txq,
            kni: None,
            received_bufs: (0..Self::RX_BURST_MAX).map(|_| MaybeUninit::uninit()).collect(),
            received_bufs_ptr: vec![ptr::null_mut(); Self::RX_BURST_MAX],
            received_index_l: 0,
            received_index_h: 0,
        }
    }
    /// Gets the MTU of the interface
    pub fn get_mtu(&self) -> std::io::Result<u16> {
        let mut result = MaybeUninit::uninit();
        unsafe {
            let errno = ffi::rte_eth_dev_get_mtu(self.port_id.raw(), result.as_mut_ptr());
            if errno == 0 {
                Ok(result.assume_init())
            } else {
                Err(std::io::Error::from_raw_os_error(errno))
            }
        }
    }
    /// Sets the MTU of the interface
    pub fn set_mtu(&mut self, mtu: u16) -> std::io::Result<()> {
        unsafe {
            let errno = ffi::rte_eth_dev_set_mtu(self.port_id.raw(), mtu);
            if errno == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(errno))
            }
        }
    }

    /// Receives a burst of packets from the receive queue, up to a maximum
    /// of 32 packets.
    /// Returns one received frame and its ownership
    pub fn receive_one(&mut self) -> Option<Mbuf> {
        if self.received_index_l == self.received_index_h {
            let len = unsafe { ffi::_rte_eth_rx_burst(self.port_id.0, self.rxq.0, self.received_bufs_ptr.as_mut_ptr(), Self::RX_BURST_MAX as u16) };
            if len == 0 {
                return None;
            }
            #[cfg(feature = "metrics")]
                self.received.as_ref().unwrap().record(len as u64);

            self.received_index_l = 0;
            self.received_index_h = len as _;

            unsafe {
                for i in 0..len as usize {
                    self.received_bufs[i] = MaybeUninit::new(Mbuf::from_ptr(self.received_bufs_ptr[i]));
                }
            }
        }

        unsafe {
            let buf = self.received_bufs[self.received_index_l].as_ptr().read();
            self.received_index_l += 1;
            Some(buf)
        }
    }

    /// Sends the packets to the transmit queue.
    pub fn transmit(&self, packets: Vec<Mbuf>) {
        let mut ptrs = packets.into_iter().map(Mbuf::into_ptr).collect::<Vec<_>>();

        loop {
            let to_send = ptrs.len() as u16;
            let sent = unsafe { ffi::_rte_eth_tx_burst(self.port_id.0, self.txq.0, ptrs.as_mut_ptr(), to_send) };

            if sent > 0 {
                #[cfg(feature = "metrics")]
                    self.transmitted.as_ref().unwrap().record(sent as u64);

                if to_send - sent > 0 {
                    // still have packets not sent. tx queue is full but still making
                    // progress. we will keep trying until all packets are sent. drains
                    // the ones already sent first and try again on the rest.
                    let _drained = ptrs.drain(..sent as usize).collect::<Vec<_>>();
                } else {
                    break;
                }
            } else {
                // tx queue is full and we can't make progress, start dropping packets
                // to avoid potentially stuck in an endless loop.
                #[cfg(feature = "metrics")]
                    self.dropped.as_ref().unwrap().record(ptrs.len() as u64);

                super::mbuf_free_bulk(ptrs);
                break;
            }
        }
    }

    /// Returns a handle to send packets to the associated KNI interface.
    pub fn kni(&self) -> Option<&KniTxQueue> { self.kni.as_ref() }

    /// Sets the TX queue for the KNI interface.
    fn set_kni(&mut self, kni: KniTxQueue) { self.kni = Some(kni); }

    /// Returns the MAC address of the port.
    pub fn mac_addr(&self) -> MacAddr { super::eth_macaddr_get(self.port_id.0) }
}
unsafe impl Send for PortQueue {}
impl Drop for PortQueue {
    fn drop(&mut self) {
        for i in self.received_index_l..self.received_index_h {
            unsafe {
                std::ptr::drop_in_place(self.received_bufs[i].as_mut_ptr());
            }
        }
    }
}

/// Error indicating failed to initialize the port.
#[derive(Debug, Error)]
pub enum PortError {
    /// Port is not found.
    #[error("Port {0} is not found.")]
    NotFound(String),

    #[error("Port is not bound to any cores.")]
    CoreNotBound,

    /// The maximum number of RX queues is less than the number of cores
    /// assigned to the port.
    #[error("Insufficient number of RX queues '{0}'.")]
    InsufficientRxQueues(usize),

    /// The maximum number of TX queues is less than the number of cores
    /// assigned to the port.
    #[error("Insufficient number of TX queues '{0}'.")]
    InsufficientTxQueues(usize),
}

/// An Ethernet device port.
pub struct Port {
    pub id: PortId,
    pub name: String,
    pub device: String,
    pub queues: HashMap<CoreId, PortQueue>,
    pub kni: Option<Kni>,
    pub dev_info: ffi::rte_eth_dev_info,
}

impl Port {
    /// Returns the port id.
    pub fn id(&self) -> PortId { self.id }

    /// Returns the application assigned logical name of the port.
    ///
    /// For applications with more than one port, this name can be used to
    /// identifer the port.
    pub fn name(&self) -> &str { self.name.as_str() }

    /// Returns the MAC address of the port.
    pub fn mac_addr(&self) -> MacAddr { super::eth_macaddr_get(self.id.0) }

    /// Returns the available port queues.
    pub fn queues(&self) -> &HashMap<CoreId, PortQueue> { &self.queues }

    /// Returns the KNI.
    pub fn kni(&mut self) -> Option<&mut Kni> { self.kni.as_mut() }

    /// Starts the port. This is the final step before packets can be
    /// received or transmitted on this port. Promiscuous mode is also
    /// enabled automatically.
    ///
    /// # Errors
    ///
    /// If the port fails to start, `DpdkError` is returned.
    pub fn start(&mut self) -> Result<()> {
        unsafe {
            ffi::rte_eth_dev_start(self.id.0).into_result(DpdkError::from_errno)?;
        }

        info!("started port {}.", self.name());
        Ok(())
    }

    /// Stops the port.
    pub fn stop(&mut self) {
        unsafe {
            ffi::rte_eth_dev_stop(self.id.0);
        }

        info!("stopped port {}.", self.name());
    }

    #[cfg(feature = "metrics")]
    pub fn stats(&self) -> super::PortStats { super::PortStats::build(self) }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let info = self.dev_info;
        f.debug_struct(&self.name())
            .field("device", &self.device)
            .field("port", &self.id.0)
            .field("mac", &format_args!("\"{}\"", self.mac_addr()))
            .field("driver", &info.driver_name.as_str())
            .field("rx_offload", &format_args!("{:#x}", info.rx_offload_capa))
            .field("tx_offload", &format_args!("{:#x}", info.tx_offload_capa))
            .field("max_rxq", &info.max_rx_queues)
            .field("max_txq", &info.max_tx_queues)
            .field("socket", &self.id.socket_id().map_or(-1, |s| s.0))
            .finish()
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        debug!("freeing {}.", self.name);

        unsafe {
            ffi::rte_eth_dev_close(self.id.0);
        }
    }
}

/// Builds a port from the configuration values.
pub struct PortBuilder<'a> {
    name: String,
    device: String,
    port_id: PortId,
    dev_info: ffi::rte_eth_dev_info,
    cores: Vec<CoreId>,
    mempools: MempoolMap<'a>,
    rxd: u16,
    txd: u16,
}

impl<'a> PortBuilder<'a> {
    /// Creates a new `PortBuilder` with a logical name and device name.
    ///
    /// The device name can be the following
    ///   * PCIe address, for example `0000:02:00.0`
    ///   * DPDK virtual device, for example `net_[pcap0|null0|tap0]`
    ///
    /// # Errors
    ///
    /// If the device is not found, `DpdkError` is returned.
    pub fn new(name: String, device: String) -> Result<Self> {
        let mut port_id = 0u16;
        unsafe {
            ffi::rte_eth_dev_get_port_by_name(device.clone().into_cstring().as_ptr(), &mut port_id).into_result(DpdkError::from_errno)?;
        }

        let port_id = PortId(port_id);
        debug!("{} is {:?}.", name, port_id);

        let mut dev_info = ffi::rte_eth_dev_info::default();
        unsafe {
            ffi::rte_eth_dev_info_get(port_id.0, &mut dev_info);
        }

        Ok(PortBuilder {
            name,
            device,
            port_id,
            dev_info,
            cores: vec![CoreId::new(0)],
            mempools: Default::default(),
            rxd: 0,
            txd: 0,
        })
    }

    /// Sets the processing cores assigned to the port.
    ///
    /// Each core assigned will receive from and transmit through the port
    /// independently using the run-to-completion model.
    ///
    /// # Errors
    ///
    /// If either the maximum number of RX or TX queues is less than the
    /// number of cores assigned, `PortError` is returned.
    pub fn cores(&mut self, cores: &[CoreId]) -> Result<&mut Self> {
        ensure!(!cores.is_empty(), PortError::CoreNotBound);

        let mut cores = cores.to_vec();
        cores.sort();
        cores.dedup();
        let len = cores.len() as u16;

        ensure!(self.dev_info.max_rx_queues >= len, PortError::InsufficientRxQueues(self.dev_info.max_rx_queues as usize));
        ensure!(self.dev_info.max_tx_queues >= len, PortError::InsufficientTxQueues(self.dev_info.max_tx_queues as usize));

        self.cores = cores;
        Ok(self)
    }

    /// Sets the receive and transmit queues' capacity.
    ///
    /// `rxd` is the receive queue capacity and `txd` is the trasmit queue
    /// capacity. The values are checked against the descriptor limits of
    /// the Ethernet device, and are adjusted if they exceed the boundaries.
    ///
    /// # Errors
    ///
    /// If the adjustment failed, `DpdkError` is returned.
    pub fn rx_tx_queue_capacity(&mut self, rxd: usize, txd: usize) -> Result<&mut Self> {
        let mut rxd2 = rxd as u16;
        let mut txd2 = txd as u16;

        unsafe {
            ffi::rte_eth_dev_adjust_nb_rx_tx_desc(self.port_id.0, &mut rxd2, &mut txd2).into_result(DpdkError::from_errno)?;
        }

        info!(cond: rxd2 != rxd as u16, message = "adjusted rxd.", before = rxd, after = rxd2);
        info!(cond: txd2 != txd as u16, message = "adjusted txd.", before = txd, after = txd2);

        self.rxd = rxd2;
        self.txd = txd2;
        Ok(self)
    }

    /// Sets the available mempools.
    pub fn mempools(&'a mut self, mempools: &'a mut [Mempool]) -> &'a mut Self {
        self.mempools = MempoolMap::new(mempools);
        self
    }

    /// Creates the `Port`.
    #[allow(clippy::cognitive_complexity)]
    pub fn finish(&mut self, promiscuous: bool, multicast: bool, with_kni: bool) -> anyhow::Result<Port> {
        let len = self.cores.len() as u16;
        let mut conf = ffi::rte_eth_conf::default();

        // turns on receive side scaling if port has multiple cores.
        if len > 1 {
            conf.rxmode.mq_mode = ffi::rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
            conf.rx_adv_conf.rss_conf.rss_hf = DEFAULT_RSS_HF & self.dev_info.flow_type_rss_offloads;
        }

        // turns on optimization for fast release of mbufs.
        if self.dev_info.tx_offload_capa & ffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64 > 0 {
            conf.txmode.offloads |= ffi::DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            debug!("turned on optimization for fast release of mbufs.");
        }

        // must configure the device first before everything else.
        unsafe {
            ffi::rte_eth_dev_configure(self.port_id.0, len, len, &conf).into_result(DpdkError::from_errno)?;
        }

        // if the port is virtual, we will allocate it to the socket of
        // the first assigned core.
        let socket_id = self.port_id.socket_id().unwrap_or_else(|| self.cores[0].socket_id());
        debug!("{} connected to {:?}.", self.name, socket_id);

        // the socket determines which pool to allocate mbufs from.
        let mempool = self.mempools.get_raw(socket_id)?;

        // if the port has kni enabled, we will allocate an interface.
        let kni = if with_kni {
            let kni = KniBuilder::new(mempool)
                .name(&self.name)
                .port_id(self.port_id)
                .mac_addr(super::eth_macaddr_get(self.port_id.raw()))
                .finish()?;
            Some(kni)
        } else {
            None
        };

        let mut queues = HashMap::new();

        // for each core, we setup a rx/tx queue pair. for simplicity, we
        // will use the same index for both queues.
        for (idx, &core_id) in self.cores.iter().enumerate() {
            // for best performance, the port and cores should connect to
            // the same socket.
            warn!(
                cond: core_id.socket_id() != socket_id,
                message = "core socket does not match port socket.",
                core = ?core_id,
                core_socket = core_id.socket_id().0,
                port_socket = socket_id.0
            );

            // configures the RX queue with defaults
            let rxq = RxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_rx_queue_setup(self.port_id.0, rxq.0, self.rxd, socket_id.0 as raw::c_uint, ptr::null(), mempool).into_result(DpdkError::from_errno)?;
            }

            // configures the TX queue with defaults
            let txq = TxQueueIndex(idx as u16);
            unsafe {
                ffi::rte_eth_tx_queue_setup(self.port_id.0, txq.0, self.txd, socket_id.0 as raw::c_uint, ptr::null()).into_result(DpdkError::from_errno)?;
            }

            #[cfg(feature = "pcap-dump")]
                {
                    pcap::capture_queue(self.port_id, self.name.as_str(), core_id, RxTxQueue::Rx(rxq))?;

                    pcap::capture_queue(self.port_id, self.name.as_str(), core_id, RxTxQueue::Tx(txq))?;
                }

            let mut q = PortQueue::new(self.port_id, rxq, txq);

            if let Some(kni) = &kni {
                q.set_kni(kni.txq());
            }

            #[cfg(feature = "metrics")]
                q.set_counters(&self.name, core_id);

            queues.insert(core_id, q);
            debug!("initialized port queue for {:?}.", core_id);
        }

        unsafe {
            // sets the port's promiscuous mode.
            if promiscuous {
                ffi::rte_eth_promiscuous_enable(self.port_id.0);
            } else {
                ffi::rte_eth_promiscuous_disable(self.port_id.0);
            }

            // sets the port's multicast mode.
            if multicast {
                ffi::rte_eth_allmulticast_enable(self.port_id.0);
            } else {
                ffi::rte_eth_allmulticast_disable(self.port_id.0);
            }
        }

        info!("initialized port {}.", self.name);

        Ok(Port {
            id: self.port_id,
            name: self.name.clone(),
            device: self.device.clone(),
            queues,
            kni,
            dev_info: self.dev_info,
        })
    }
}
