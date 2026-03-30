use std::net::{Ipv4Addr};

pub struct Packet {
    pub data: Vec<u8>,
}

pub struct EncryptedPacket {
    pub nonce: [u8; 24],
    pub data: Vec<u8>,
}

pub struct IpPool {
    pub next: u8,
}

impl IpPool {
    pub fn assign(&mut self) -> Ipv4Addr {
        let ip = Ipv4Addr::new(10, 0, 0, self.next);
        self.next += 1;
        ip
    }
}

pub const TYPE_HANDSHAKE: u8 = 0x01;
//pub const TYPE_DATA: u8 = 0x02;
pub const EXCHANGE: u8 = 0x03;