use synapsis::network::{RegisterData, PutData, MessageData, Message, UID};
use synapsis::crypto::{
    gen_pub, enc_pub, dec_pub, PublicKeyPair,
    gen_ver, sign, VerifyKeyPair,
    gen_prv, enc_prv, dec_prv, PrivateKey,
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::blocking::{Client, Response};
use std::time::{SystemTime, Duration, UNIX_EPOCH};

struct Connection {
    address: String,
    client: Client,
    username: String,
    pkp: PublicKeyPair,
    pkv: VerifyKeyPair,
    sk: PrivateKey,
}

impl Connection {
    fn new(address: &str, username: &str, password: &str) -> Result<Self, reqwest::Error> {
        let pub_keypair = gen_pub(username, password);
        let ver_keypair = gen_ver(username, password);
        let sk = gen_prv(username, password);

        let client = reqwest::blocking::Client::new();
        let data = RegisterData {
            username: username.to_string(),
            pkp: pub_keypair.pubkey(),
            pkv: ver_keypair.pubkey(),
        };
        register_keys(&format!("{}/register", address)[..], &client, data)?;

        Ok(Connection {
            address: address.to_string(),
            client: client.clone(),
            username: username.to_string(),
            pkp: pub_keypair,
            pkv: ver_keypair,
            sk: sk,
        })
    }
}

struct Messages {
    conn: Connection,
    with: String, 
    sent: Option<(String, Duration, Option<UID>)>,
    recv: Option<(String, Duration, Option<UID>)>,
}

impl Messages {
    fn new(conn: Connection, with: String) -> Self {
        let sent = get_sent_message_head(&conn, with.clone());
        let recv = get_recv_message_head(&conn, with.clone());
        Messages {
            conn: conn,
            with: with,
            sent: sent,
            recv: recv,
        }
    }
}

impl Iterator for Messages {
    type Item = (String, String, Duration);

    fn next(&mut self) -> Option<Self::Item> {
        if self.sent.is_some() && self.recv.is_some() {
            if self.sent.as_ref().unwrap().1 >= self.recv.as_ref().unwrap().1 {
                let sent = self.sent.take().unwrap();
                self.sent = if let Some(uid) = sent.2 {
                    get_sent_message(&self.conn, self.with.clone(), uid)
                } else { None };
                Some((sent.0, self.conn.username.clone(), sent.1))
            } else {
                let recv = self.recv.take().unwrap();
                self.recv = if let Some(uid) = recv.2 {
                    get_recv_message(&self.conn, self.with.clone(), uid)
                } else { None };
                Some((recv.0, self.with.clone(), recv.1))
            }
        } else if self.sent.is_some() {
            let sent = self.sent.take().unwrap();
            self.sent = if let Some(uid) = sent.2 {
                get_sent_message(&self.conn, self.with.clone(), uid)
            } else { None };
            Some((sent.0, self.conn.username.clone(), sent.1))
        } else if self.recv.is_some() {
            let recv = self.sent.take().unwrap();
            self.recv = if let Some(uid) = recv.2 {
                get_recv_message(&self.conn, self.with.clone(), uid)
            } else { None };
            Some((recv.0, self.with.clone(), recv.1))
        } else {
            None
        }
    }
}

fn get_sent_message(conn: &Connection, to: String, uid: UID) -> Option<(String, Duration, Option<UID>)> {
    let message = get_data(&format!("{}/{}/{}/{}", conn.address, conn.username.clone(), to, uid)[..], &conn.client).ok()?.text().ok()?;
    let message_de: Message = serde_json::from_str(&message[..]).ok()?;
    let message = dec_prv(&message_de.message_cc.1[..], &conn.sk, &message_de.message_cc.0[..]);
    Some((String::from_utf8(message).ok()?, message_de.timestamp, message_de.prev))
}

fn get_sent_message_head(conn: &Connection, to: String) -> Option<(String, Duration, Option<UID>)> {
    let data = get_data(&format!("{}/{}/{}/head", conn.address, conn.username.clone(), to)[..], &conn.client).ok()?.text().ok()?;
    let head: Option<UID> = serde_json::from_str(&data[..]).unwrap();
    let head: UID = head?;
    get_sent_message(conn, to, head)
}

fn get_recv_message(conn: &Connection, from: String, uid: UID) -> Option<(String, Duration, Option<UID>)> {
    let message = get_data(&format!("{}/{}/{}/{}", conn.address, from, conn.username.clone(), uid)[..], &conn.client).ok()?.text().ok()?;
    let message_de: Message = serde_json::from_str(&message[..]).ok()?;
    let message = dec_pub(&message_de.message[..], &conn.pkp).ok()?;
    Some((String::from_utf8(message).ok()?, message_de.timestamp, message_de.prev))
}

fn get_recv_message_head(conn: &Connection, from: String) -> Option<(String, Duration, Option<UID>)> {
    let data = get_data(&format!("{}/{}/{}/head", conn.address, from, conn.username.clone())[..], &conn.client).ok()?.text().ok()?;
    let head: Option<UID> = serde_json::from_str(&data[..]).ok()?;
    let head: UID = head?;
    get_recv_message(conn, from, head)
}

fn send_chat_message(conn: &mut Connection, data: &MessageData) -> Result<reqwest::StatusCode, reqwest::StatusCode> {
    let head = get_data(&format!("{}/{}/{}/head", &conn.address[..], conn.username, data.to)[..], &conn.client)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|res|
            if res.status().is_success() {
                Ok(Some(res.text()))
            } else if res.status() == reqwest::StatusCode::NOT_FOUND {
                Ok(None)
            } else {
                Err(res.status())
            })?;
    let head = match head {
        Some(Ok(a)) => Some(a),
        Some(Err(_)) => return Err(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        None => None,
    };
    let head = head.and_then(|uid|
        Some(serde_json::from_str::<u64>(&uid[..])));
    let head = match head {
        Some(Ok(a)) => Some(a),
        Some(Err(_)) => return Err(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        None => None,
    };

    //TODO: cache this
    let pkp = get_data(&format!("{}/{}/pkp", &conn.address[..], data.to)[..], &conn.client) 
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|res|
            if res.status().is_success() {
                Ok(res.text())
            } else {
                Err(res.status())
            })
        .and_then(|res| res.map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR))
        .and_then(|pkp|
            serde_json::from_str::<PublicKeyPair>(&pkp[..])
                .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR))?;
    let message = enc_pub(data.message.as_bytes(), &pkp);
    let message_cc = enc_prv(data.message.as_bytes(), &mut conn.sk);
    let uid: UID = OsRng.next_u64();
    let timestamp = (SystemTime::now().duration_since(UNIX_EPOCH)).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = Message {
            message: message,
            message_cc: message_cc,
            timestamp: timestamp,
            prev: head,
        };
    let message = serde_json::to_string(&message)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature = sign(&message.as_bytes()[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;

    let msg_data = PutData {
        data: message,
        signature: signature,
    };
    put_data(&format!("{}/{}/{}/{}", &conn.address, conn.username, data.to, uid)[..], &conn.client, msg_data)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|res|
            if res.status().is_success() {
                Ok(res.status())
            } else {
                Err(res.status())
            })?;

    let uid_ser = serde_json::to_string(&uid)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature = sign(&uid_ser.as_bytes()[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let uid_data = PutData {
        data: uid_ser,
        signature: signature,
    };
    put_data(&format!("{}/{}/{}/head", &conn.address[..], conn.username, data.to)[..], &conn.client, uid_data)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|res|
            if res.status().is_success() {
                Ok(res.status())
            } else {
                Err(res.status())
            })
}

fn register_keys(address: &str, client: &Client, data: RegisterData) -> reqwest::Result<Response> {
    client.post(address)
        .json(&data)
        .send()
}

fn put_data(address: &str, client: &Client, data: PutData) -> reqwest::Result<Response> {
    client.put(address)
        .json(&data)
        .send()
}

fn get_data(address: &str, client: &Client) -> reqwest::Result<Response> {
    client.get(address)
        .send()
}

fn main() {
    let address = "http://localhost:8000";

    let username = "some_user";
    let password = "some_pass";

    let mut conn1 = Connection::new(address, username, password).unwrap();

    let username = "some_other_user";
    let password = "some_other_pass";

    let mut conn2 = Connection::new(address, username, password).unwrap();

    send_chat_message(&mut conn1, &MessageData {
        to: conn2.username.clone(),
        message: "Hello, world!".to_string(),
    }).unwrap();

    send_chat_message(&mut conn2, &MessageData {
        to: conn1.username.clone(),
        message: "Hello kind sir. How do you do?".to_string(),
    }).unwrap();

    send_chat_message(&mut conn1, &MessageData {
        to: conn2.username.clone(),
        message: "Quite well my fine fellow.".to_string(),
    }).unwrap();

    send_chat_message(&mut conn1, &MessageData {
        to: conn2.username.clone(),
        message: "Oh, dear, it seems Samuel is having an affair with a new mistress".to_string(),
    }).unwrap();

    send_chat_message(&mut conn2, &MessageData {
        to: conn1.username.clone(),
        message: "Nothing good ever comes from that putrid man.".to_string(),
    }).unwrap();

    send_chat_message(&mut conn1, &MessageData {
        to: conn2.username.clone(),
        message: "Quite true indeed. Say, shall we meet at the inn to morrow, that we may talk of matters of state?".to_string(),
    }).unwrap();

    send_chat_message(&mut conn2, &MessageData {
        to: conn1.username.clone(),
        message: "That would be splendid.".to_string(),
    }).unwrap();

    let messages = Messages::new(conn1, conn2.username.clone());
    for message in messages {
        println!("({}) {}: {}", message.2.as_nanos(), message.1, message.0);
    }
}

