use serde::{Serialize, Deserialize};
use crate::crypto::{PublicKeyPair, VerifyKeyPair};
use ed25519_dalek::Signature;

#[derive(Serialize, Deserialize)]
pub struct RegisterData {
    pub username: String,
    pub pkp: PublicKeyPair,
    pub pkv: VerifyKeyPair,
}

#[derive(Serialize, Deserialize)]
pub struct PutData {
    pub data: String,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct MessageData {
    pub from: String,
    pub to: String,
    pub message: String,
}

type UID = u64;

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub message: String,
    pub uid: UID,
    pub prev: Option<UID>,
    pub next: Option<UID>,
}

