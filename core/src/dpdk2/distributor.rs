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
use failure::Fallible;
use std::fmt;
use std::os::raw;
use std::ptr::{self, NonNull};

/// Component to pass packets to workers, with dynamic load balancing. The
/// distributor will ensure that no two packets that have the same flow id,
/// or tag, in the mbuf will be processed on different cores at the same time.
pub(crate) struct Distributor {
    name: String,
    raw: NonNull<ffi::rte_distributor>,
}

impl Distributor {
    /// Returns the raw struct needed for FFI calls.
    #[inline]
    fn raw_mut(&mut self) -> &mut ffi::rte_distributor {
        unsafe { self.raw.as_mut() }
    }

    /// Processes a set of packets by distributing them among workers that
    /// request packets.
    pub(crate) fn distribute(&mut self, packets: &mut Vec<NonNull<ffi::rte_mbuf>>) {
        let len = packets.len();

        unsafe {
            let processed = ffi::rte_distributor_process(
                self.raw_mut(),
                packets.as_mut_ptr() as *mut *mut ffi::rte_mbuf,
                len as raw::c_uint,
            ) as usize;

            // should not happen.
            debug_assert!(len == processed, "some packets are not processed.");

            packets.set_len(0);
        }
    }

    /// Flush the distributor component, so that there are no in-flight or
    /// backlogged packets awaiting processing.
    pub(crate) fn flush(&mut self) {
        unsafe {
            ffi::rte_distributor_flush(self.raw_mut());
        }
    }
}

impl fmt::Debug for Distributor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Distributor")
            .field("name", &self.name)
            .finish()
    }
}

unsafe impl Send for Distributor {}

/// Component to receive packets from the distributor.
pub(crate) struct Worker {
    name: String,
    worker_id: raw::c_uint,
    distributor: NonNull<ffi::rte_distributor>,
}

impl Worker {
    /// Polls the distributor for packets, up to 8 packets.
    pub(crate) fn poll(&mut self, packets: &mut Vec<NonNull<ffi::rte_mbuf>>) {
        debug_assert!(packets.capacity() >= 8);

        unsafe {
            let len = ffi::rte_distributor_poll_pkt(
                self.distributor.as_mut(),
                self.worker_id,
                packets.as_mut_ptr() as *mut *mut ffi::rte_mbuf,
            );

            if len > 0 {
                packets.set_len(len as usize);
            }
        }
    }

    /// Requests new packets from the distributor.
    pub(crate) fn request(&mut self) {
        unsafe {
            ffi::rte_distributor_request_pkt(
                self.distributor.as_mut(),
                self.worker_id,
                ptr::null_mut(),
                0,
            );
        }
    }
}

impl fmt::Debug for Worker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Worker")
            .field("name", &self.name)
            .field("worker_id", &self.worker_id)
            .finish()
    }
}

unsafe impl Send for Worker {}

/// Creates a new packet distributor and the associated workers.
pub(crate) fn distributor<S: Into<String>>(
    name: S,
    socket: SocketId,
    workers: usize,
) -> Fallible<(Distributor, Vec<Worker>)> {
    let name = name.into();

    let raw = unsafe {
        ffi::rte_distributor_create(
            name.clone().to_cstring().as_ptr(),
            socket.raw() as raw::c_uint,
            workers as raw::c_uint,
            ffi::rte_distributor_alg_type::RTE_DIST_ALG_BURST,
        )
        .to_dpdk_result()?
    };

    let dist = Distributor { name, raw };
    let workers = (0..workers)
        .map(|id| Worker {
            name: dist.name.clone(),
            worker_id: id as raw::c_uint,
            distributor: dist.raw,
        })
        .collect::<Vec<_>>();

    Ok((dist, workers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsule::dpdk2::{self, LcoreId, Mbuf};

    fn gen_packets(len: usize) -> Vec<NonNull<ffi::rte_mbuf>> {
        (0..len)
            .map(|idx| {
                let ptr = Mbuf::new().unwrap().into_ptr();
                unsafe {
                    let mut mbuf = NonNull::new_unchecked(ptr);
                    // tags each packet so they can be evenly distributed.
                    mbuf.as_mut().__bindgen_anon_4.hash.usr = idx as u32;
                    mbuf
                }
            })
            .collect::<Vec<_>>()
    }

    #[capsule::test(mempool_capacity = 31)]
    fn run_distributor() -> Fallible<()> {
        let (mut dist, mut workers) = distributor("dist", SocketId(0), 2)?;
        assert_eq!(2, workers.len());

        let mut handles = Vec::new();
        for lcore in 1..3 {
            let mut worker = workers.pop().unwrap();
            handles.push(dpdk2::spawn(LcoreId(lcore), move || {
                worker.request();

                let mut batch = Vec::with_capacity(10);
                while batch.is_empty() {
                    worker.poll(&mut batch);
                }

                // the max batch size is 8 packets per poll.
                assert_eq!(8, batch.len());
            })?)
        }

        // we expect even distribution.
        let mut packets = gen_packets(16);
        dist.distribute(&mut packets);
        assert!(packets.is_empty());

        dist.flush();

        handles
            .into_iter()
            .for_each(|handle| handle.join().expect("panic!"));

        Ok(())
    }
}
