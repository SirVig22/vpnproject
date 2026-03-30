use std::io::{Read, Write};
use std::thread;
use std::sync::{Arc, Mutex};
use tun::Configuration;
use std::sync::mpsc::{Sender, Receiver};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use crate::packet::Packet;

pub fn start(tx: Sender<(IpAddr, Packet)>, rx: Receiver<Packet>) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Configuration::default();

    config
        .name("tun0")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();

    let dev = Arc::new(Mutex::new(tun::create(&config)?));
    let dev_reader = Arc::clone(&dev);
    let dev_writer = Arc::clone(&dev);

    thread::spawn(move || {
        loop {
            let mut buf = [0u8; 1500];
            let amount = dev_reader.lock().unwrap().read(&mut buf).unwrap();
            let version = buf[0] >> 4;

            let dest_ip = match version {
                4 => {
                    if let Ok(header) = Ipv4HeaderSlice::from_slice(&buf[..amount]) {
                        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::from(header.destination())))
                    } else {
                        continue;
                    }
                }

                6 => {
                    if let Ok(header) = Ipv6HeaderSlice::from_slice(&buf[..amount]) {
                        IpAddr::V6(Ipv6Addr::from(header.destination()))
                    } else {
                        continue;
                    }
                }

                _ => continue,
            };

            tx.send((dest_ip, Packet { data: buf[..amount].to_vec() })).unwrap();

        }
    });

    thread::spawn(move || {
        while let Ok(packet) = rx.recv() {
            dev_writer.lock().unwrap().write_all(&packet.data).unwrap();
        }
    });

    Ok(())
}