use std::sync::mpsc::channel;
use std::thread;
use std::sync::mpsc::{Sender, Receiver};
use std::process::Command;

use chacha20poly1305::{
    aead::{KeyInit},
    XChaCha20Poly1305, Key
};

mod tun;
mod crypto;
mod transport;
mod udp;
mod packet;
mod keyexch;

fn main() {
    setup_server_routing();

    let bind = "0.0.0.0:5353";

    let (tx_send_raw_packet, rx_encrypt) = channel();
    let (tx_send_encrypted_packet, rx_encap) = channel();
    let (tx_send_received_encrypted_packet, rx_decrypt) = channel();
    let (tx_send_decrypted_packet, rx_receive_packet) = channel();
    let (tx_udp_server, rx_decap) = channel();
    let (tx_udp_client, rx_sendc) = channel();
    let (tx_key, rx_key): (Sender<[u8; 32]>, Receiver<[u8; 32]>) = channel();

    let key_store = keyexch::KeyStore::new();

    let session_key = rx_key.recv().expect("never received session key");
    let key = Key::from_slice(&session_key);

    let cipher_encrypt = XChaCha20Poly1305::new(key);
    let cipher_decrypt = XChaCha20Poly1305::new(key);

    tun::start(tx_send_raw_packet, rx_receive_packet).unwrap();

    thread::spawn(move || {
        crypto::encrypt(rx_encrypt, tx_send_encrypted_packet, cipher_encrypt).unwrap();
    });

    thread::spawn(move || {
        crypto::decrypt(rx_decrypt, tx_send_decrypted_packet, cipher_decrypt).unwrap();
    });

    thread::spawn(move || {
        transport::transport(rx_encap, tx_send_received_encrypted_packet, rx_decap, tx_udp_client).unwrap();
    });

    thread::spawn(move || {
        udp::run_server(rx_sendc, bind, tx_udp_server, tx_key).unwrap();
    });

    thread::park();
}

fn setup_server_routing() {
    Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status()
        .expect("failed to enable ip forwarding");

    Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE"])
        .status()
        .expect("failed to set up NAT");
}