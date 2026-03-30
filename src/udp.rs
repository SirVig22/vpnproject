use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr, UdpSocket, IpAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use crate::packet::{Packet, IpPool, TYPE_HANDSHAKE, EXCHANGE};
use crate::keyexch::{KeyExchange, KeyStore};

type ClientMap = Arc<Mutex<HashMap<SocketAddr, Ipv4Addr>>>;
type VpnMap = Arc<Mutex<HashMap<Ipv4Addr, SocketAddr>>>;
type V6Map = Arc<Mutex<HashMap<IpAddr, Ipv4Addr>>>;

pub fn run_server(arrivepack: Receiver<(IpAddr, Packet)>, bind_addr: &str, sendpack: Sender<Packet>, tx_key: Sender<[u8; 32]>) -> Result<(), Box<dyn std::error::Error>> {

    let socket = Arc::new(UdpSocket::bind(bind_addr)?);
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));
    let vpn_map: VpnMap = Arc::new(Mutex::new(HashMap::new()));
    let ip_pool = Arc::new(Mutex::new(IpPool { next: 2 }));
    let v6_map: V6Map = Arc::new(Mutex::new(HashMap::new()));
    let key_store = KeyStore::new(); // moved inside function

    let socket_out = Arc::clone(&socket);
    let vpn_map_clone = Arc::clone(&vpn_map);
    let v6_map_clone = Arc::clone(&v6_map);
    let _key_store_t1 = key_store.clone();
    let key_store_t2 = key_store.clone();
    let socket_in = Arc::clone(&socket);
    let clients_t2 = Arc::clone(&clients);
    let vpn_map_t2 = Arc::clone(&vpn_map);
    let ip_pool_t2 = Arc::clone(&ip_pool);
    let v6_map_t2 = Arc::clone(&v6_map);

    //SEND
    thread::spawn(move || {
        while let Ok((addr, packet)) = arrivepack.recv() {
            let vpn_map = vpn_map_clone.lock().unwrap();
            let v6_map = v6_map_clone.lock().unwrap();

            match addr {
                IpAddr::V4(v4) => {
                    if let Some(client) = vpn_map.get(&v4) {
                        let _ = socket_out.send_to(&packet.data, client);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Some(v4) = v6_map.get(&IpAddr::V6(v6)) {
                        if let Some(client) = vpn_map.get(v4) {
                            let _ = socket_out.send_to(&packet.data, client);
                        }
                    }
                }
            }
        }
    });

    //RECEIVE
    thread::spawn(move || {
        let mut buf = [0u8; 1500];
        loop {
            let (len, src_addr) = match socket_in.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("recv_from error: {}", e);
                    break;
                }
            };

            let data = buf[..len].to_vec();

            { // new client
                let mut map = clients_t2.lock().unwrap();
                if !map.contains_key(&src_addr) {
                    let vpn_ip = ip_pool_t2.lock().unwrap().assign();

                    map.insert(src_addr, vpn_ip);
                    vpn_map_t2.lock().unwrap().insert(vpn_ip, src_addr);

                    let mut handshake = vec![TYPE_HANDSHAKE];
                    handshake.extend_from_slice(&vpn_ip.octets());
                    let _ = socket_in.send_to(&handshake, src_addr);

                    let ipv6 = IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, vpn_ip.octets()[3] as u16));
                    v6_map_t2.lock().unwrap().insert(ipv6, vpn_ip);

                    let serverk = KeyExchange::new();
                    let server_pub_bytes = serverk.public_key.to_bytes();

                    let mut kexchange = vec![EXCHANGE];
                    kexchange.extend_from_slice(&server_pub_bytes);
                    let _ = socket_in.send_to(&kexchange, src_addr);

                    key_store_t2.insert_pending(vpn_ip, serverk);

                    println!("New client: {} assigned VPN IP {}", src_addr, vpn_ip);
                    if let Some(k) = key_store_t2.get_session_key(&vpn_ip) {
                        let _ = tx_key.send(k);
                    }
                    continue;
                }
            }

            match buf[0] {
                EXCHANGE => {
                    let client_pub_bytes: [u8; 32] = match data[1..33].try_into() {
                        Ok(b) => b,
                        Err(_) => { eprintln!("invalid key length from {}", src_addr); continue; }
                    };

                    let vpn_ip = {
                        let map = clients_t2.lock().unwrap();
                        match map.get(&src_addr).copied() {
                            Some(ip) => ip,
                            None => { eprintln!("EXCHANGE from unknown client {}", src_addr); continue; }
                        }
                    };

                    if let Err(e) = key_store_t2.complete_exchange(vpn_ip, &client_pub_bytes, b"vpn-session-v1") {
                        eprintln!("key exchange failed for {}: {}", src_addr, e);
                    }
                }
                _ => {
                    let _ = sendpack.send(Packet { data });
                }
            }
        }
    });

    Ok(())
}