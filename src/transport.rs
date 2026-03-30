use std::sync::mpsc::{Receiver, Sender};
use std::net::IpAddr;
use std::error::Error;
use std::thread;
use crate::packet::{Packet, EncryptedPacket};

pub fn transport(rxc: Receiver<(IpAddr, EncryptedPacket)>, txc: Sender<EncryptedPacket>, rxs: Receiver<Packet>, txs: Sender<(IpAddr, Packet)>) -> Result<(), Box<dyn Error>> {

    thread::spawn(move || {
        while let Ok((ip, packet)) = rxc.recv() {
            let enc = encapsulate(packet);
            txs.send((ip, enc)).ok();
        }
    });

    thread::spawn(move || {
        while let Ok(packet) = rxs.recv() {
            let dec = decapsulate(packet);
            txc.send(dec).ok();
        }
    });
    Ok(())
}

pub fn encapsulate(packet: EncryptedPacket) -> Packet {
    let mut data = Vec::with_capacity(24 + packet.data.len());
    data.extend_from_slice(&packet.nonce);
    data.extend_from_slice(&packet.data);
    Packet { data }
}

pub fn decapsulate(packet: Packet) -> EncryptedPacket {
    let nonce: [u8; 24] = packet.data[..24]
        .try_into()
        .expect("packet too short: missing nonce");
    let data = packet.data[24..].to_vec();
    EncryptedPacket { nonce, data }
}