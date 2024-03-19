use crypto::{
    aes::{
        self,
        KeySize,
    },
    digest::Digest,
    sha2::Sha256,
};
use serde::{
    Serialize,
    Deserialize,
};
use std::{
    io::Cursor, iter::repeat
};
use byteorder::{BigEndian, ReadBytesExt};
use p256::elliptic_curve::rand_core::{
    self, CryptoRng, RngCore, impls, OsRng
};
use ecies_ed25519::{self, Error::InvalidSecretKeyBytes};
use ed25519_dalek::{self, Keypair, Signature, Signer, Verifier};

struct Sha256Rng(Sha256);

impl Sha256Rng {
    pub fn new(username: &str, password: &str) -> Self {
        let mut rng = Sha256Rng(Sha256::new());
        rng.0.input_str(username);
        rng.0.input_str(password);
        rng
    }
}

impl CryptoRng for Sha256Rng { }

impl RngCore for Sha256Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes: Vec<u8> = repeat(0u8).take(self.0.output_bytes()).collect();
        self.0.result(&mut bytes[..]);
        self.0.reset();
        self.0.input(&bytes[..]);
        Cursor::new(bytes).read_u64::<BigEndian>().unwrap()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(self.fill_bytes(dest))
    }
}

pub fn next_u128() -> u128 {
  let mut bytes: [u8;16] = [0; 16];
  OsRng.fill_bytes(bytes.as_mut());
  let out: u128 = u128::from_be_bytes(bytes);
  out
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey(pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct PublicKeyPair {
    pub pk: ecies_ed25519::PublicKey,
    pub sk: Option<ecies_ed25519::SecretKey>,
}

impl PublicKeyPair {
    pub fn pubkey(&self) -> PublicKeyPair {
        PublicKeyPair {
            pk: self.pk.clone(),
            sk: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyPair {
    Keypair(Keypair),
    PubKey(ed25519_dalek::PublicKey),
}

impl VerifyKeyPair {
    pub fn pubkey(&self) -> VerifyKeyPair {
        match self {
            VerifyKeyPair::Keypair(kp) => VerifyKeyPair::PubKey(kp.public.clone()),
            VerifyKeyPair::PubKey(pk) => VerifyKeyPair::PubKey(pk.clone()),
        }
    }
}

pub fn gen_prv(username: &str, password: &str) -> PrivateKey {
    let mut key: Vec<u8> = repeat(0u8).take(32).collect();
    let mut rng = Sha256Rng::new(username, password);
    rng.fill_bytes(&mut key[..]);
    PrivateKey(key)
}

pub fn gen_pub(username: &str, password: &str) -> PublicKeyPair {
    let mut rng = Sha256Rng::new(username, password);
    let (secret, public) = ecies_ed25519::generate_keypair(&mut rng);
    PublicKeyPair {
        pk: public,
        sk: Some(secret),
    }
}

pub fn gen_ver(username: &str, password: &str) -> VerifyKeyPair {
    let mut rng = Sha256Rng::new(username, password);
    let keypair: Keypair = Keypair::generate(&mut rng);
    VerifyKeyPair::Keypair(keypair)
}

pub fn enc_prv(message: &[u8], key: &PrivateKey) -> (Vec<u8>, Vec<u8>) {
    let mut output: Vec<u8> = repeat(0u8).take(message.len()).collect();
    let mut nonce: Vec<u8> = repeat(0u8).take(16).collect();
    OsRng.fill_bytes(&mut nonce[..]);
    let mut cipher = aes::ctr(KeySize::KeySize256, &key.0, &nonce); 
    cipher.process(message, &mut output[..]);
    (nonce, output)
}

pub fn dec_prv(message: &[u8], key: &PrivateKey, nonce: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = repeat(0u8).take(message.len()).collect();
    let mut cipher = aes::ctr(KeySize::KeySize256, &key.0, nonce); 
    cipher.process(message, &mut output[..]);
    output
}

pub fn enc_pub(message: &[u8], keys: &PublicKeyPair) -> Vec<u8> {
    let mut rng = OsRng;
    let output = ecies_ed25519::encrypt(&keys.pk, message, &mut rng).unwrap();
    output
}

pub fn dec_pub(message: &[u8], keys: &PublicKeyPair) -> Result<Vec<u8>, ecies_ed25519::Error> {
    let output = ecies_ed25519::decrypt(keys.sk.as_ref().ok_or(InvalidSecretKeyBytes)?, message);
    output
}

pub fn sign(message: &[u8], keys: &VerifyKeyPair) -> Option<Signature> {
    match keys {
        VerifyKeyPair::Keypair(keypair) => Some(keypair.sign(message)),
        VerifyKeyPair::PubKey(_) => None,
    }
}

pub fn vrfy(message: &[u8], signature: Signature, keys: &VerifyKeyPair) -> bool {
    match keys {
        VerifyKeyPair::Keypair(keypair) => keypair.verify(message, &signature).is_ok(),
        VerifyKeyPair::PubKey(pk) => pk.verify(message, &signature).is_ok(),
    }
}

#[cfg(test)]
mod test {
    use super::{
        gen_prv, enc_prv, dec_prv,
        gen_pub, enc_pub, dec_pub,
        gen_ver, sign, vrfy,
    };
    
    #[test]
    fn sign_verify() {
        let username = "some_user";
        let password = "some_pass";
        let keys = gen_ver(username, password);

        let message = b"This is a message.";
        let signature = sign(message, &keys).unwrap();
        assert!(vrfy(message, signature, &keys));
    }
 
    #[test]
    #[should_panic]
    fn sign_verify_no_sk() {
        let username = "some_user";
        let password = "some_pass";
        let keys = gen_ver(username, password);
        let keys = keys.pubkey();

        let message = b"This is a message.";
        sign(message, &keys).unwrap();
    }
 
    #[test]
    fn sign_verify_wrong_signature() {
        let username = "some_user";
        let password = "some_pass";
        let keys1 = gen_ver(username, password);

        let username = "some_other_user";
        let password = "some_other_pass";
        let keys2 = gen_ver(username, password);

        let message = b"This is a message.";
        let signature = sign(message, &keys1).unwrap();
        assert!(!vrfy(message, signature, &keys2));
    }
    /*
    #[test]
    fn verify_key_pair_serde_json() {
        let username = "some_user";
        let password = "some_pass";
        let keys = gen_ver(username, password);

        let json = serde_json::ser::to_string(&keys).unwrap();
        let keys_de: VerifyKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(
            keys.pk.to_encoded_point(false).as_bytes(),
            keys_de.pk.to_encoded_point(false).as_bytes(),
        );
        assert_eq!(
            keys.sk.unwrap().to_bytes(),
            keys_de.sk.unwrap().to_bytes(),
        );
    }
    
    #[test]
    fn verify_key_pair_serde_json_sk_none() {
        let username = "some_user";
        let password = "some_pass";
        let mut keys = gen_ver(username, password);
        keys.sk = None;

        let json = serde_json::ser::to_string(&keys).unwrap();
        let keys_de: VerifyKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(
            keys.pk.to_encoded_point(false).as_bytes(),
            keys_de.pk.to_encoded_point(false).as_bytes(),
        );
        assert_eq!(
            keys.sk.is_none(),
            keys_de.sk.is_none(),
        );
    }

    #[test]
    fn sign_verify() {
        let username = "some_user";
        let password = "some_pass";
        let keys = gen_ver(username, password);

        let message = b"This is a message.";
        let signature = sign(message, &keys).unwrap();
        assert!(vrfy(message, signature, &keys));
    }
 
    #[test]
    #[should_panic]
    fn sign_verify_no_sk() {
        let username = "some_user";
        let password = "some_pass";
        let mut keys = gen_ver(username, password);
        keys.sk = None;

        let message = b"This is a message.";
        let signature = sign(message, &keys).unwrap();
    }
 
    #[test]
    fn sign_verify_wrong_signature() {
        let username = "some_user";
        let password = "some_pass";
        let keys1 = gen_ver(username, password);

        let username = "some_other_user";
        let password = "some_other_pass";
        let keys2 = gen_ver(username, password);

        let message = b"This is a message.";
        let signature = sign(message, &keys1).unwrap();
        assert!(!vrfy(message, signature, &keys2));
    }
    */

    #[test]
    fn encrypt_prv() {
        let username = "some_user";
        let password = "some_pass";
        let mut key = gen_prv(username, password);

        let message = b"This is a message.";
        let (nonce, ciphertext) = enc_prv(message, &mut key);
        let message_de = dec_prv(&ciphertext[..], &key, &nonce[..]);
        assert_eq!(message, &message_de[..]);
    }

    #[test]
    fn encrypt_prv_wrong_key() {
        let username = "some_user";
        let password = "some_pass";
        let mut key1 = gen_prv(username, password);

        let username = "some_other_user";
        let password = "some_other_pass";
        let key2 = gen_prv(username, password);

        let message = b"This is a message.";
        let (nonce, ciphertext) = enc_prv(message, &mut key1);
        let message_de = dec_prv(&ciphertext[..], &key2, &nonce[..]);
        assert_ne!(message, &message_de[..]);
    }

    #[test]
    fn encrypt_prv_wrong_nonce() {
        let username = "some_user";
        let password = "some_pass";
        let mut key = gen_prv(username, password);

        let message = b"This is a message.";
        let (nonce, ciphertext) = enc_prv(message, &mut key);
        let (nonce_wrong, _) = enc_prv(message, &mut key);    // replace nonce with next
        let message_de = dec_prv(&ciphertext[..], &key, &nonce_wrong[..]);
        assert_ne!(nonce, nonce_wrong);
        assert_ne!(message, &message_de[..]);
    }

    #[test]
    fn encrypt_pub() {
        let username = "some_user";
        let password = "some_pass";
        let keys = gen_pub(username, password);

        let message = b"This is a message.";
        let ciphertext = enc_pub(message, &keys);
        let message_de = dec_pub(&ciphertext[..], &keys).unwrap();
        assert_eq!(message, &message_de[..]);
    }

    #[test]
    #[should_panic]
    fn encrypt_pub_no_sk() {
        let username = "some_user";
        let password = "some_pass";
        let mut keys = gen_pub(username, password);
        keys.sk = None;

        let message = b"This is a message.";
        let ciphertext = enc_pub(message, &keys);
        dec_pub(&ciphertext[..], &keys).unwrap();
    }

    #[test]
    #[should_panic]
    fn encrypt_pub_wrong_sk() {
        let username = "some_user";
        let password = "some_pass";
        let mut keys1 = gen_pub(username, password);

        let username = "some_other_user";
        let password = "some_other_pass";
        let mut keys2 = gen_pub(username, password);

        let message = b"This is a message.";
        let ciphertext = enc_pub(message, &mut keys1);
        let message_de = dec_pub(&ciphertext[..], &mut keys2).unwrap();
        assert_eq!(message, &message_de[..]);
    }

}

