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

use super::{Mempool, Port, PortId};
use crate::dpdk::DpdkError;
use crate::ffi::{self, AsStr, ToResult};
use anyhow::Result;
use std::ptr::NonNull;

/// Port stats collector.
pub struct PortStats {
    id: PortId,
    name: String,
}

impl PortStats {
    /// Builds a collector from the port.
    pub fn build(port: &Port) -> Self {
        PortStats {
            id: port.id(),
            name: port.name().to_owned(),
        }
    }

    /// Returns the port name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

}

/// Mempool stats collector.
pub struct MempoolStats {
    raw: NonNull<ffi::rte_mempool>,
}

impl MempoolStats {
    /// Builds a collector from the port.
    pub fn build(mempool: &Mempool) -> Self {
        MempoolStats {
            raw: unsafe {
                NonNull::new_unchecked(
                    mempool.raw() as *const ffi::rte_mempool as *mut ffi::rte_mempool
                )
            },
        }
    }

    fn raw(&self) -> &ffi::rte_mempool {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the name of the `Mempool`.
    fn name(&self) -> &str {
        self.raw().name[..].as_str()
    }

}

/// Send mempool stats across threads.
unsafe impl Send for MempoolStats {}
unsafe impl Sync for MempoolStats {}
