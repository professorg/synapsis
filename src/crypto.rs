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
    ser::{SerializeStruct, Serializer},
    de::{self, Deserializer, Visitor, SeqAccess, MapAccess},
};
use std::{
    fmt,
    iter::repeat,
    io::Cursor,
};
use byteorder::{BigEndian, ReadBytesExt};
use p256::{
    EncodedPoint,
    elliptic_curve::rand_core::{
        self, CryptoRng, RngCore, impls, OsRng
    },
    ecdsa::{
        SigningKey, VerifyingKey, Signature,
        signature::{Signer, Verifier},
    },
};
use ecies_ed25519::{self, PublicKey, SecretKey, Error::InvalidSecretKeyBytes};

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

#[derive(Serialize, Deserialize)]
pub struct PrivateKey(Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct PublicKeyPair {
    pk: PublicKey,
    sk: Option<SecretKey>,
}

/*
pub struct VerifyKeyPair {
    pk: VerifyingKey,
    sk: Option<SigningKey>,
}

impl Serialize for VerifyKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("VerifyKeyPair", 2)?;
        state.serialize_field("pk", &self.pk.to_encoded_point(false).as_bytes())?;
        let mut sk_vec = Vec::new();
        let sk = match self.sk.as_ref() {
            None => None,
            Some(x) => {
                sk_vec = Vec::from(x.to_bytes().as_slice());
                Some(())
            },
        };
        state.serialize_field("sk", &sk.and(Some(&sk_vec[..])))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for VerifyKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field { Pk, Sk }

        struct VerifyKeyPairVisitor;

        impl<'de> Visitor<'de> for VerifyKeyPairVisitor {
            type Value = VerifyKeyPair;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct VerifyKeyPair")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<VerifyKeyPair, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let pk: Vec<u8> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let sk: Option<Vec<u8>> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                let ep = EncodedPoint::from_bytes(pk)
                        .map_err(|_| de::Error::custom("could not get encoded point from bytes"))?;
                let pk = VerifyingKey::from_encoded_point(&ep)
                    .map_err(|_| de::Error::custom("could not get verifying key from encoded point"))?;
                let sk = match sk {
                    None => None,
                    Some(x) => Some(
                        SigningKey::from_bytes(&x[..])
                            .map_err(|_| de::Error::custom("could not get signing key from bytes"))?
                    ),
                };

                Ok(VerifyKeyPair{
                    pk: pk,
                    sk: sk,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<VerifyKeyPair, V::Error>
            where
                V: MapAccess<'de>
            {
                let mut pk = None;
                let mut sk = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Pk => {
                            if pk.is_some() {
                                return Err(de::Error::duplicate_field("pk"));
                            }
                            let a = map.next_value();
                            pk = Some(a?);
                        }
                        Field::Sk => {
                            if sk.is_some() {
                                return Err(de::Error::duplicate_field("sk"));
                            }
                            sk = Some(map.next_value()?);
                        }
                    }
                }
                let pk: Vec<u8> = pk.ok_or_else(|| de::Error::missing_field("pk"))?;
                let sk: Option<Vec<u8>> = sk.ok_or_else(|| de::Error::missing_field("sk"))?;

                let ep = EncodedPoint::from_bytes(pk)
                        .map_err(|_| de::Error::custom("could not get encoded point from bytes"))?;
                let pk = VerifyingKey::from_encoded_point(&ep)
                    .map_err(|_| de::Error::custom("could not get verifying key from encoded point"))?;
                let sk = match sk {
                    None => None,
                    Some(x) => Some(
                        SigningKey::from_bytes(&x[..])
                            .map_err(|_| de::Error::custom("could not get signing key from bytes"))?
                    ),
                };

                Ok(VerifyKeyPair{
                    pk: pk,
                    sk: sk,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["pk", "sk"];
        deserializer.deserialize_struct("VerifyKeyPair", FIELDS, VerifyKeyPairVisitor)
    }
}
*/

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

/*
pub fn gen_ver(username: &str, password: &str) -> VerifyKeyPair {
    let signing_key = SigningKey::random(Sha256Rng::new(username, password));
    let verifying_key = signing_key.verify_key();
    VerifyKeyPair{
        pk: verifying_key,
        sk: Some(signing_key),
    }
}
*/

pub fn enc_prv(message: &[u8], key: &mut PrivateKey) -> (Vec<u8>, Vec<u8>) {
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

/*
pub fn sign(message: &[u8], keys: &VerifyKeyPair) -> Option<Signature> {
    let sk = keys.sk.as_ref()?;
    let signature = sk.sign(message);
    Some(signature)
}

pub fn vrfy(message: &[u8], signature: Signature, keys: &VerifyKeyPair) -> bool {
    keys.pk.verify(message, &signature).is_ok()
}
*/

#[cfg(test)]
mod test {
    use super::{
        gen_prv, PrivateKey, enc_prv, dec_prv,
        gen_pub, PublicKeyPair, enc_pub, dec_pub,
        gen_ver, VerifyKeyPair, sign, vrfy,
    };
    use p256::ecdsa::signature::{Signer, Verifier};
    
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
        let mut key2 = gen_prv(username, password);

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
        let (nonce, _) = enc_prv(message, &mut key);    // replace nonce with next
        let message_de = dec_prv(&ciphertext[..], &key, &nonce[..]);
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
        let message_de = dec_pub(&ciphertext[..], &keys).unwrap();
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

