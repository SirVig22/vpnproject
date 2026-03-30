use std::sync::mpsc::{Receiver, Sender};
use std::net::IpAddr;
use crate::packet::{Packet, EncryptedPacket};

use chacha20poly1305::{
    aead::{Aead, Error, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, Key
};

pub fn encrypt(rx: Receiver<(IpAddr, Packet)>, tx: Sender<(IpAddr, EncryptedPacket)>, cipher: XChaCha20Poly1305) -> Result<(), Error> {

    while let Ok((ip, packet)) = rx.recv() {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipherdata = cipher.encrypt(&nonce, packet.data.as_ref())?;

        let encrypted_packet = EncryptedPacket {
            nonce: nonce.into(),
            data: cipherdata,
        };

        tx.send((ip, encrypted_packet)).unwrap();
    }
    Ok(())
}

pub fn decrypt(rx: Receiver<EncryptedPacket>, tx: Sender<Packet>, cipher: XChaCha20Poly1305) -> Result<(), Error> {

    while let Ok(packet) = rx.recv() {
        let packet_bytes = cipher.decrypt(&packet.nonce.into(), packet.data.as_ref())?;

        let decrypted_packet = Packet { data: packet_bytes };

        tx.send(decrypted_packet).unwrap();
    }

    Ok(())
}