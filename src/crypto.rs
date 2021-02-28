use crypto::sha2::Sha256;
use serde::{Serialize, Deserialize};
use rand_core::{RngCore, Error, impls};
use rust_elgamal::{EncryptionKey, DecryptionKey};

struct Sha256Rng(Sha256);

impl Sha256Rng {
}

impl RngCore for Sha256Rng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!();
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!();
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unimplemented!();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        unimplemented!();
    }
}

pub struct PrivateKey(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct PublicKeyPair {
    pk: EncryptionKey,
    sk: DecryptionKey,
}

pub fn gen_prv() {
    unimplemented!();
}

pub fn gen_pub() -> PublicKeyPair {
    unimplemented!();
}

pub fn gen_ver() -> PublicKeyPair {
    unimplemented!();
}

