use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

pub struct KeyExchange {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    pub fn derive_session_key(self, peer_public_key_bytes: &[u8; 32], info: &[u8]) -> Result<[u8; 32], &'static str> {
        let peer_pub = PublicKey::from(*peer_public_key_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_pub);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(info, &mut session_key)
            .map_err(|_| "HKDF expand failed")?;
        Ok(session_key)
    }
}

// Stores session keys and pending KeyExchange instances per VPN IP
#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<Mutex<KeyStoreInner>>,
}

struct KeyStoreInner {
    session_keys: HashMap<Ipv4Addr, [u8; 32]>,
    pending: HashMap<Ipv4Addr, KeyExchange>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(KeyStoreInner {
                session_keys: HashMap::new(),
                pending: HashMap::new(),
            })),
        }
    }

    // Store a pending KeyExchange (before the peer replies)
    pub fn insert_pending(&self, ip: Ipv4Addr, kex: KeyExchange) {
        self.inner.lock().unwrap().pending.insert(ip, kex);
    }

    // Complete the exchange: consumes the pending KeyExchange, derives and stores the session key
    pub fn complete_exchange(&self, ip: Ipv4Addr, peer_pub_bytes: &[u8; 32], info: &[u8]) -> Result<(), &'static str> {
        let kex = self.inner.lock().unwrap()
            .pending.remove(&ip)
            .ok_or("no pending exchange for this IP")?;

        let session_key = kex.derive_session_key(peer_pub_bytes, info)?;
        self.inner.lock().unwrap().session_keys.insert(ip, session_key);
        Ok(())
    }

    // Retrieve a session key for encryption/decryption
    pub fn get_session_key(&self, ip: &Ipv4Addr) -> Option<[u8; 32]> {
        self.inner.lock().unwrap().session_keys.get(ip).copied()
    }

    // Remove all data for an IP (e.g. on disconnect)
    pub fn remove(&self, ip: &Ipv4Addr) {
        let mut inner = self.inner.lock().unwrap();
        inner.session_keys.remove(ip);
        inner.pending.remove(ip);
    }
}

//
//pub fn keyexch() {
//    let alice = KeyExchange::new();
//    let bob   = KeyExchange::new();
//
//    let alice_pub_bytes = alice.public_key.to_bytes();
//    let bob_pub_bytes   = bob.public_key.to_bytes();
//
//    let context = b"vpn-session-v1";
//
//    let alice_key = alice
//        .derive_session_key(&bob_pub_bytes, context)
//        .expect("Alice key derivation failed");
//
//    let bob_key = bob
//        .derive_session_key(&alice_pub_bytes, context)
//        .expect("Bob key derivation failed");
//
//    println!("Alice session key: {}", hex::encode(alice_key));
//    println!("Bob   session key: {}", hex::encode(bob_key));
//    assert_eq!(alice_key, bob_key, "Keys must match!");
//    println!("Keys match — secure channel ready.");
//}