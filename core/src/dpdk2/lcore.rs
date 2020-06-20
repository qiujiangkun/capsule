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
use crate::ffi;
use failure::Fallible;
use std::boxed::Box;
use std::cell::UnsafeCell;
use std::fmt;
use std::os::raw;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::thread::Result;

/// An opaque identifier for a logical execution unit of the processor.
#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LcoreId(pub(crate) raw::c_uint);

impl LcoreId {
    /// Any lcore to indicate that no thread affinity is set.
    pub(crate) const ANY: Self = LcoreId(raw::c_uint::MAX);

    /// The last valid lcore.
    pub(crate) const LAST: Self = LcoreId(ffi::RTE_MAX_LCORE - 1);

    /// Returns the ID of the current execution unit or `LcoreId::ANY` when
    /// called from a non-EAL thread.
    #[inline]
    pub(crate) fn current() -> LcoreId {
        unsafe { LcoreId(ffi::_rte_lcore_id()) }
    }

    /// Returns the ID of the main lcore.
    #[inline]
    pub(crate) fn main() -> LcoreId {
        unsafe { LcoreId(ffi::rte_get_master_lcore()) }
    }

    /// Returns the number of enabled lcores on the system.
    #[inline]
    pub(crate) fn len() -> usize {
        unsafe { ffi::rte_lcore_count() as usize }
    }

    /// Returns an iterator over all the enabled lcores.
    #[inline]
    pub(crate) fn iter(skip_main: bool) -> LcoreIter {
        LcoreIter::new(skip_main)
    }

    /// Returns the ID of the physical CPU socket of the lcore.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn socket(&self) -> SocketId {
        unsafe { SocketId(ffi::rte_lcore_to_socket_id(self.raw()) as raw::c_int) }
    }

    /// Returns the raw value needed for FFI calls.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[inline]
    pub(crate) fn raw(&self) -> raw::c_uint {
        self.0
    }
}

impl fmt::Debug for LcoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lcore{}", self.0)
    }
}

/// An iterator that iterates through all the available lcores.
pub(crate) struct LcoreIter {
    current: raw::c_uint,
    skip_main: raw::c_int,
}

impl LcoreIter {
    /// Creates a new lcore iterator.
    pub(crate) fn new(skip_main: bool) -> Self {
        LcoreIter {
            // starts at u32 max and let `rte_get_next_lcore` wraps around to 0.
            current: raw::c_uint::MAX,
            skip_main: if skip_main { 1 } else { 0 },
        }
    }
}

impl Iterator for LcoreIter {
    type Item = LcoreId;

    fn next(&mut self) -> Option<Self::Item> {
        self.current = unsafe { ffi::rte_get_next_lcore(self.current, self.skip_main, 0) };
        match self.current {
            ffi::RTE_MAX_LCORE => None,
            _ => Some(LcoreId(self.current)),
        }
    }
}

/// The argument passed to `ffi::lcore_function_t`.
struct LaunchArg<F, T>
where
    F: FnOnce() -> T,
{
    f: Option<F>,
    ret: Arc<UnsafeCell<Option<Result<T>>>>,
}

/// The function passed to `ffi::rte_eal_remote_launch`.
unsafe extern "C" fn lcore_run<F, T>(arg: *mut raw::c_void) -> raw::c_int
where
    F: FnOnce() -> T,
{
    let mut arg = Box::from_raw(arg as *mut LaunchArg<F, T>);

    // takes the ownership of the spawned closure. must have ownership
    // so it can be moved and called.
    let f = arg.f.take().unwrap();

    // in case the closure panics, let's not crash the app.
    let result = panic::catch_unwind(AssertUnwindSafe(move || f()));

    // stores the result so it can be retrieved later on the master.
    *arg.ret.get() = Some(result);

    0
}

/// Similar to `std::thread::JoinHandle`, used to join on an lcore execution.
pub(crate) struct JoinHandle<T> {
    lcore: LcoreId,
    ret: Arc<UnsafeCell<Option<Result<T>>>>,
}

impl<T> JoinHandle<T> {
    /// Waits for the lcore to finish executing the spawned closure.
    pub(crate) fn join(self) -> Result<T> {
        unsafe {
            let _ = ffi::rte_eal_wait_lcore(self.lcore.raw());
            (*self.ret.get()).take().unwrap()
        }
    }
}

/// Spawns a new lcore execution.
///
/// Similar to `std::thread::spawn`. One major difference is that lcores are
/// created at EAL initialization. Rather than creating a new lcore, this will
/// spawn a new execution on an existing lcore.
pub(crate) fn spawn<F, T>(lcore: LcoreId, f: F) -> Fallible<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let ret = Arc::new(UnsafeCell::new(None));
    let arg = Box::new(LaunchArg {
        f: Some(f),
        ret: ret.clone(),
    });

    unsafe {
        let ptr = Box::into_raw(arg) as *mut raw::c_void;
        ffi::rte_eal_remote_launch(Some(lcore_run::<F, T>), ptr, lcore.raw()).to_dpdk_result()?;
    }

    Ok(JoinHandle { lcore, ret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[capsule::test]
    fn get_current_lcore_id_from_eal() -> Fallible<()> {
        let lcore_id = super::spawn(LcoreId(1), LcoreId::current)?
            .join()
            .expect("panic!");
        assert_eq!(LcoreId(1), lcore_id);

        Ok(())
    }

    #[capsule::test]
    fn get_current_lcore_id_from_non_eal() {
        let lcore_id = thread::spawn(LcoreId::current).join().expect("panic!");
        assert_eq!(LcoreId::ANY, lcore_id);
    }

    #[capsule::test]
    fn get_main_lcore_id() {
        assert_eq!(LcoreId(0), LcoreId::main());
    }

    #[capsule::test]
    fn get_lcore_len() {
        assert_eq!(2, LcoreId::len());
    }

    #[capsule::test]
    fn iterate_lcores() {
        let n = LcoreId::iter(false).count();
        assert_eq!(LcoreId::len(), n);

        let n = LcoreId::iter(true).count();
        assert_eq!(LcoreId::len() - 1, n);
    }

    #[capsule::test]
    fn get_lcore_socket() {
        assert_eq!(SocketId(0), LcoreId(0).socket());
    }
}
