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

mod lcore;
mod mempool;
mod port;

pub(crate) use self::lcore::*;
pub(crate) use self::mempool::*;
pub(crate) use self::port::*;
#[allow(unreachable_pub)]
pub use crate::dpdk::Mbuf;

use crate::debug;
use crate::ffi::{self, AsStr, ToCString, ToResult};
use crate::net::MacAddr;
use failure::{Fail, Fallible};
use std::fmt;
use std::os::raw;

/// An error generated in `libdpdk`.
///
/// When an FFI call fails, the `errno` is translated into `DpdkError`.
#[derive(Debug, Fail)]
#[fail(display = "{}", _0)]
pub(crate) struct DpdkError(String);

impl DpdkError {
    /// Returns the `DpdkError` for the most recent failure on the current
    /// core.
    #[inline]
    pub(crate) fn new() -> Self {
        DpdkError::from_errno(-1)
    }

    /// Returns the `DpdkError` for a specific `errno`.
    #[inline]
    fn from_errno(errno: raw::c_int) -> Self {
        let errno = if errno == -1 {
            unsafe { ffi::_rte_errno() }
        } else {
            -errno
        };
        DpdkError(unsafe { ffi::rte_strerror(errno).as_str().into() })
    }
}

/// Simplify DPDK FFI binding's return to a `Result` type.
pub(crate) trait ToDpdkResult: ToResult {
    fn to_dpdk_result(self) -> Fallible<Self::Ok>;
}

impl<T> ToDpdkResult for *mut T {
    #[inline]
    fn to_dpdk_result(self) -> Fallible<Self::Ok> {
        self.to_result(|_| DpdkError::new())
    }
}

impl ToDpdkResult for raw::c_int {
    #[inline]
    fn to_dpdk_result(self) -> Fallible<Self::Ok> {
        self.to_result(DpdkError::from_errno)
    }
}

/// An opaque identifier for a physical CPU socket.
///
/// A socket is also known as a NUMA node. On a multi-socket system, for best
/// performance, ensure that the cores and memory used for packet processing
/// are in the same socket as the network interface card.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) struct SocketId(raw::c_int);

impl SocketId {
    /// A socket ID representing any NUMA socket.
    pub(crate) const ANY: Self = SocketId(-1);

    /// Returns all the socket IDs detected on the system.
    #[inline]
    pub(crate) fn all() -> Vec<SocketId> {
        unsafe {
            (0..ffi::rte_socket_count())
                .map(|idx| ffi::rte_socket_id_by_idx(idx).to_dpdk_result())
                .filter_map(|res| match res {
                    Ok(id) => Some(SocketId(id as raw::c_int)),
                    Err(_) => None,
                })
                .collect::<Vec<_>>()
        }
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> raw::c_int {
        self.0
    }
}

impl fmt::Debug for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket{}", self.0)
    }
}

/// Initializes the Environment Abstraction Layer (EAL).
pub(crate) fn eal_init<S: Into<String>>(args: Vec<S>) -> Fallible<()> {
    let args = args
        .into_iter()
        .map(|s| Into::<String>::into(s).to_cstring())
        .collect::<Vec<_>>();
    debug!(arguments=?args);

    let mut ptrs = args
        .iter()
        .map(|s| s.as_ptr() as *mut raw::c_char)
        .collect::<Vec<_>>();
    let len = ptrs.len() as raw::c_int;

    let parsed = unsafe { ffi::rte_eal_init(len, ptrs.as_mut_ptr()).to_dpdk_result()? };
    debug!("EAL parsed {} arguments.", parsed);

    Ok(())
}

/// Cleans up the Environment Abstraction Layer (EAL).
pub(crate) fn eal_cleanup() -> Fallible<()> {
    unsafe { ffi::rte_eal_cleanup() }
        .to_dpdk_result()
        .map(|_| ())
}

/// Returns the `MacAddr` of a port.
///
/// # Errors
///
/// Returns an error if the `port_id` is invalid.
fn eth_macaddr_get(port_id: u16) -> Fallible<MacAddr> {
    let mut addr = ffi::rte_ether_addr::default();
    unsafe {
        ffi::rte_eth_macaddr_get(port_id, &mut addr).to_dpdk_result()?;
    }
    Ok(addr.addr_bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[capsule::test]
    fn get_all_sockets() {
        assert!(!SocketId::all().is_empty());
    }
}
