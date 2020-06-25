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

use crate::dpdk2::Mbuf;
use futures::channel::mpsc::UnboundedSender;
use std::cell::Cell;
use std::collections::HashMap;

/// Abstraction over the unbounded sender. Sender half of the unbounded
/// channel that can forward mbufs to the lcore where TX is running.
#[derive(Clone)]
pub(crate) struct PortForwarder(UnboundedSender<Mbuf>);

impl PortForwarder {
    pub(crate) fn forward(&self, packet: Mbuf) -> Result<(), Mbuf> {
        self.0.unbounded_send(packet).map_err(|e| e.into_inner())
    }
}

impl From<UnboundedSender<Mbuf>> for PortForwarder {
    fn from(sender: UnboundedSender<Mbuf>) -> Self {
        PortForwarder(sender)
    }
}

#[derive(Clone)]
pub(crate) struct PortForwarders {
    forwarders: HashMap<String, PortForwarder>,
}

impl PortForwarders {
    pub(crate) fn new() -> Self {
        PortForwarders {
            forwarders: HashMap::new(),
        }
    }

    pub(crate) fn add<S: Into<String>>(&mut self, port: S, forwarder: PortForwarder) {
        self.forwarders.insert(port.into(), forwarder);
    }

    pub(crate) fn forward(&self, port: &str, packet: Mbuf) -> Result<(), Mbuf> {
        match self.forwarders.get(port) {
            Some(f) => f.forward(packet),
            None => Err(packet),
        }
    }
}

thread_local! {
    /// forwarders for each lcore.
    pub(crate) static FORWARDERS: Cell<Option<PortForwarders>> = Cell::new(None);
}
