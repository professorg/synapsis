use std::{collections::hash_map::DefaultHasher, hash::Hasher, time::Duration};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::crypto::{PublicKeyPair, VerifyKeyPair};
use ed25519_dalek::Signature;

#[derive(Serialize, Deserialize)]
pub struct RegisterData {
    pub user_id: UserID,
    pub pkp: PublicKeyPair,
    pub pkv: VerifyKeyPair,
}

#[derive(Serialize, Deserialize)]
pub struct PutData {
    pub data: Value,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct UserVerification {
    pub nonce: RegisterData,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct MessageData {
    pub to: UserID,
    pub message: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum MessageParts {
  First(String),
  Cons(String, Box<MessageParts>),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MessageDataParts {
    pub to: UserID,
    pub message: MessageParts,
}

//TODO: how do I use this?
impl MessageParts {
  fn new(message: String, max_size: usize) -> MessageParts {
    message
      .chars()
      .collect::<Vec<_>>()
      .chunks(max_size)
      .fold(None, |acc, c| {
        if let Some(x) = acc {
          Some(MessageParts::Cons(c.iter().collect::<String>(), Box::new(x)))
        } else {
          Some(MessageParts::First(c.iter().collect::<String>()))
        }
      })
      .unwrap()
  }
}

pub fn to_message_parts(data: &MessageData, max_size: usize) -> MessageDataParts {
  MessageDataParts {
    to: data.to,
    message: MessageParts::new(data.message.clone(), max_size),
  }
}

// for some reason serde can't handle u128
pub type UID = u64; //u128;
pub type UserID = u64;

pub fn from_username(username: String) -> UserID {
  let mut hasher = DefaultHasher::new();
  hasher.write(&username[..].as_bytes());
  hasher.write_u8(0xff);
  hasher.finish()
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub message: Vec<u8>,
    pub message_cc: (Vec<u8>, Vec<u8>),
    pub timestamp: Duration,
    pub prev: Option<UID>,
    pub uid: UID,
}

