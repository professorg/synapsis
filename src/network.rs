use std::time::Duration;
use serde::{Serialize, Deserialize};
use serde_json::Value;
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
    pub data: Value,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct MessageData {
    pub to: String,
    pub message: String,
}

//TODO: This is way too small
pub type UID = u64;

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub message: Vec<u8>,
    pub message_cc: (Vec<u8>, Vec<u8>),
    pub timestamp: Duration,
    pub prev: Option<UID>,
    pub uid: UID,
}

