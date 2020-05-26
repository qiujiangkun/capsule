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

//! Utilities for unit tests and benchmarks.

pub mod byte_arrays;
pub mod criterion;
mod packet;
pub mod proptest;
mod rvg;

pub use self::packet::*;
pub use self::rvg::*;

use crate::dpdk2::{self, Mempool, SocketId, MEMPOOL};
use crate::metrics;
use std::ptr;
use std::sync::Once;
use std::thread;

/// Run once initialization of EAL for `cargo test`.
pub fn cargo_test_init() {
    static TEST_INIT: Once = Once::new();

    TEST_INIT.call_once(|| {
        dpdk2::eal_init(vec![
            "capsule_test",
            "-l",
            "0-1",
            "--master-lcore",
            "0",
            "--no-huge",      // allow tests to run without hugepages
            "--iova-mode=va", // allow tests to run without root privilege
            "--vdev",
            "net_null0", // a null device for RX and TX tests
            "--vdev",
            "net_ring0", // a ring-based device that can be used with assertions
            "--vdev",
            "net_tap0", // a TAP device for supported device feature tests
        ])
        .unwrap();

        let _ = metrics::init();
    });
}

/// A RAII guard that keeps the mempool in scope for the duration of the
/// test. It will unset the thread-bound mempool on drop.
#[derive(Debug)]
pub struct MempoolGuard {
    _inner: Mempool,
}

impl Drop for MempoolGuard {
    fn drop(&mut self) {
        MEMPOOL.with(|tls| tls.replace(ptr::null_mut()));
    }
}

/// Creates a new mempool for test that automatically cleans up after the
/// test completes.
pub fn new_mempool(capacity: usize, cache_size: usize) -> MempoolGuard {
    let name = format!("testpool-{:?}", thread::current().id());
    let mut mempool = Mempool::new(name, capacity, cache_size, SocketId::ANY).unwrap();
    MEMPOOL.with(|tls| tls.set(mempool.raw_mut()));
    MempoolGuard { _inner: mempool }
}
