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

use async_std::sync::{self, Receiver, Sender};
use std::mem::ManuallyDrop;

/// A shutdown trigger used to stop the runtime.
pub(crate) struct Shutdown(ManuallyDrop<Sender<()>>);

impl Shutdown {
    /// Creates a new shutdown trigger and associated wait handle.
    pub(crate) fn new() -> (Shutdown, ShutdownWait) {
        let (s, r) = sync::channel::<()>(1);
        (Shutdown(ManuallyDrop::new(s)), ShutdownWait(r))
    }

    /// Signals the runtime shutdown.
    pub(crate) fn signal(&mut self) {
        // dropping the sender half unblocks the receivers.
        unsafe {
            ManuallyDrop::drop(&mut self.0);
        }
    }
}

/// The wait handle for the runtime shutdown signal.
#[derive(Clone)]
pub(crate) struct ShutdownWait(Receiver<()>);

impl ShutdownWait {
    /// Waits for the shutdown signal.
    pub(crate) async fn wait(&self) {
        // the result doesn't matter; the future is unblocked.
        let _ = self.0.recv().await;
    }
}
