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
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::ip::v6::Ipv6;
use capsule::packets::ip::IpPacket;
use capsule::packets::{EtherTypes, Ethernet, Packet, Tcp};
use capsule::{Mbuf, Runtime2};
use colored::*;
use failure::Fallible;
use futures::prelude::*;
use signal_hook::{self, pipe};
use smol::{self, Async};
use std::os::unix::net::UnixStream;
use tracing::Level;
use tracing_subscriber::fmt;

async fn ctrl_c() -> Fallible<()> {
    let (mut read, write) = Async::<UnixStream>::pair()?;
    pipe::register(signal_hook::SIGINT, write)?;
    println!("ctrl-c to quit.");

    read.read_exact(&mut [0]).await?;
    Ok(())
}

#[inline]
fn dump_eth(packet: Mbuf) -> Fallible<()> {
    let ethernet = packet.peek::<Ethernet>()?;

    let info_fmt = format!("{:?}", ethernet).magenta().bold();
    println!("{}", info_fmt);

    match ethernet.ether_type() {
        EtherTypes::Ipv4 => dump_v4(&ethernet),
        EtherTypes::Ipv6 => dump_v6(&ethernet),
        _ => Ok(()),
    }
}

#[inline]
fn dump_v4(ethernet: &Ethernet) -> Fallible<()> {
    let v4 = ethernet.peek::<Ipv4>()?;
    let info_fmt = format!("{:?}", v4).yellow();
    println!("{}", info_fmt);

    let tcp = v4.peek::<Tcp<Ipv4>>()?;
    dump_tcp(&tcp);

    Ok(())
}

#[inline]
fn dump_v6(ethernet: &Ethernet) -> Fallible<()> {
    let v6 = ethernet.peek::<Ipv6>()?;
    let info_fmt = format!("{:?}", v6).cyan();
    println!("{}", info_fmt);

    let tcp = v6.peek::<Tcp<Ipv6>>()?;
    dump_tcp(&tcp);

    Ok(())
}

#[inline]
fn dump_tcp<T: IpPacket>(tcp: &Tcp<T>) {
    let tcp_fmt = format!("{:?}", tcp).green();
    println!("{}", tcp_fmt);

    let flow_fmt = format!("{:?}", tcp.flow()).bright_blue();
    println!("{}", flow_fmt);
}

fn main() -> Fallible<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    let guard = Runtime2::from_config(config)?
        .set_port_pipeline("eth1", dump_eth)
        .set_port_pipeline("eth2", dump_eth)
        .execute()?;

    let _ = smol::block_on(ctrl_c());

    drop(guard);

    Ok(())
}
