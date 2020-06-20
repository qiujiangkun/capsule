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

use capsule::config2::load_config;
use capsule::Runtime2;
use failure::Fallible;
use futures::prelude::*;
use signal_hook::{self, pipe};
use smol::{self, Async};
use std::os::unix::net::UnixStream;
use tracing::{debug, info, Level};
use tracing_subscriber::fmt;

async fn ctrl_c() -> Fallible<()> {
    let (mut read, write) = Async::<UnixStream>::pair()?;
    pipe::register(signal_hook::SIGINT, write)?;
    info!("ctrl-c to quit.");

    read.read_exact(&mut [0]).await?;
    Ok(())
}

fn main() -> Fallible<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    let guard = Runtime2::from_config(config)?.execute()?;

    smol::block_on(
        async {
            let _ = ctrl_c().await;
        },
    );

    drop(guard);

    Ok(())
}
