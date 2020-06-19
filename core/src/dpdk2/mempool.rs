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
use crate::ffi::{self, AsStr, ToCString};
use crate::{debug, info};
use failure::Fallible;
use std::cell::Cell;
use std::fmt;
use std::os::raw;
use std::ptr::{self, NonNull};

/// A `Mempool` is an allocator of message buffers, or `Mbuf`. For best
/// performance, each socket should have a dedicated `Mempool`.
pub(crate) struct Mempool {
    raw: NonNull<ffi::rte_mempool>,
}

impl Mempool {
    /// Creates a new `Mempool`.
    ///
    /// `capacity` is the maximum number of Mbufs in the pool. The optimum
    /// size (in terms of memory usage) is when n is a power of two minus one.
    ///
    /// `cache_size` is the per core cache size. If `cache_size` is non-zero,
    /// caching is enabled. New `Mbuf` will be retrieved first from cache,
    /// subsequently from the common pool. The cache can be disabled if
    /// `cache_size` is set to 0.
    ///
    /// `socket_id` is the socket where the memory should be allocated. The
    /// value can be `SocketId::ANY` if there is no constraint.
    pub(crate) fn new<S: Into<String>>(
        name: S,
        capacity: usize,
        cache_size: usize,
        socket_id: SocketId,
    ) -> Fallible<Self> {
        let name: String = name.into();

        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                name.clone().to_cstring().as_ptr(),
                capacity as raw::c_uint,
                cache_size as raw::c_uint,
                0,
                ffi::RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                socket_id.raw(),
            )
            .to_dpdk_result()?
        };

        info!(mempool = ?name, "pool created.");
        Ok(Self { raw })
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub(crate) fn raw(&self) -> &ffi::rte_mempool {
        unsafe { self.raw.as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    pub(crate) fn raw_mut(&mut self) -> &mut ffi::rte_mempool {
        unsafe { self.raw.as_mut() }
    }

    /// Returns the pool name.
    #[inline]
    pub(crate) fn name(&self) -> &str {
        self.raw().name[..].as_str()
    }

    /// Returns the maximum number of Mbufs in the pool.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.raw().size as usize
    }

    /// Returns the per core cache size.
    #[inline]
    pub(crate) fn cache_size(&self) -> usize {
        self.raw().cache_size as usize
    }

    /// Returns the socket the pool is allocated from.
    #[inline]
    pub(crate) fn socket(&self) -> SocketId {
        SocketId(self.raw().socket_id)
    }
}

impl fmt::Debug for Mempool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mempool")
            .field("name", &self.name())
            .field("capacity", &self.capacity())
            .field("cache_size", &self.cache_size())
            .field("socket", &self.socket())
            .finish()
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        debug!(mempool = ?self.name(), "pool freed.");
        unsafe {
            ffi::rte_mempool_free(self.raw_mut());
        }
    }
}

// make Mempool sharable across threads
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

thread_local! {
    /// The `Mempool` assigned to the core when the core is initialized.
    /// `Mbuf::new` uses this pool to allocate new buffers when executed on
    /// the core. For best performance, the `Mempool` and the core should
    /// share the same socket.
    pub(crate) static MEMPOOL: Cell<*mut ffi::rte_mempool> = Cell::new(ptr::null_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[capsule::test]
    fn create_mempool() -> Fallible<()> {
        let pool = Mempool::new("pool1", 15, 1, SocketId(0))?;

        assert_eq!("pool1", pool.name());
        assert_eq!(15, pool.capacity());
        assert_eq!(1, pool.cache_size());
        assert_eq!(SocketId(0), pool.socket());

        Ok(())
    }

    #[capsule::test]
    fn drop_mempool() -> Fallible<()> {
        let pool = Mempool::new("pool2", 7, 0, SocketId::ANY)?;

        let name = "pool2".to_string().to_cstring();
        let ptr = unsafe { ffi::rte_mempool_lookup(name.as_ptr()) };
        assert!(!ptr.is_null());

        drop(pool);

        let ptr = unsafe { ffi::rte_mempool_lookup(name.as_ptr()) };
        assert!(ptr.is_null());

        Ok(())
    }
}
