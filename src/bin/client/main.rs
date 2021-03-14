extern crate gtk;
extern crate gio;

use synapsis::{
    network::{RegisterData, PutData, MessageData, Message, UID},
    crypto::{
        gen_pub, enc_pub, dec_pub, PublicKeyPair,
        gen_ver, sign, VerifyKeyPair,
        gen_prv, enc_prv, dec_prv, PrivateKey,
    },
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::blocking::{Client, Response};
use std::{
    io::{stdin, stdout, Write},
    time::{SystemTime, Duration, UNIX_EPOCH},
};
use gtk::{
    prelude::*,
    Application, ApplicationWindow, Button,
};
use gio::prelude::*;



struct Connection {
    address: String,
    client: Client,
    username: String,
    pkp: PublicKeyPair,
    pkv: VerifyKeyPair,
    sk: PrivateKey,
}

impl Connection {
    fn new(address: &str, username: &str, password: &str, register: bool) -> Result<Self, reqwest::Error> {
        let pub_keypair = gen_pub(username, password);
        let ver_keypair = gen_ver(username, password);
        let sk = gen_prv(username, password);

        let client = reqwest::blocking::Client::new();

        if register {
            let data = RegisterData {
                username: username.to_string(),
                pkp: pub_keypair.pubkey(),
                pkv: ver_keypair.pubkey(),
            };
            register_keys(&format!("{}/register", address)[..], &client, data)?;
        }

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

struct MessageDe {
    from: String,
    message: String,
    timestamp: Duration,
    prev: Option<UID>,
    uid: UID,
}

struct Messages<'a> {
    conn: &'a Connection,
    with: String, 
    sent: Option<MessageDe>,
    recv: Option<MessageDe>,
    until: Option<UID>,
}

impl<'a> Messages<'a> {
    fn new(conn: &'a Connection, with: String, until: Option<UID>) -> Self {
        let sent = get_sent_message_head(&conn, with.clone());
        let recv = get_recv_message_head(&conn, with.clone());
        Messages {
            conn: conn,
            with: with,
            sent: sent,
            recv: recv,
            until: until,
        }
    }
}

impl<'a> Iterator for Messages<'a> {
    type Item = MessageDe;

    fn next(&mut self) -> Option<Self::Item> {
        if self.sent.is_some() && self.recv.is_some() {
            if self.sent.as_ref().unwrap().timestamp >= self.recv.as_ref().unwrap().timestamp {
                let sent = self.sent.take().unwrap();
                if let Some(until) = self.until {
                    if until == sent.uid { return None; }
                }
                self.sent = if let Some(uid) = sent.prev {
                    get_sent_message(&self.conn, self.with.clone(), uid)
                } else { None };
                Some(sent)
            } else {
                let recv = self.recv.take().unwrap();
                if let Some(until) = self.until {
                    if until == recv.uid { return None; }
                }
                self.recv = if let Some(uid) = recv.prev {
                    get_recv_message(&self.conn, self.with.clone(), uid)
                } else { None };
                Some(recv)
            }
        } else if self.sent.is_some() {
            let sent = self.sent.take().unwrap();
            if let Some(until) = self.until {
                if until == sent.uid { return None; }
            }
            self.sent = if let Some(uid) = sent.prev {
                get_sent_message(&self.conn, self.with.clone(), uid)
            } else { None };
            Some(sent)
        } else if self.recv.is_some() {
            let recv = self.recv.take().unwrap();
            if let Some(until) = self.until {
                if until == recv.uid { return None; }
            }
            self.recv = if let Some(uid) = recv.prev {
                get_recv_message(&self.conn, self.with.clone(), uid)
            } else { None };
            Some(recv)
        } else {
            None
        }
    }
}

fn get_sent_message(conn: &Connection, to: String, uid: UID) -> Option<MessageDe> {
    let message = get_data(&format!("{}/{}/{}/{}", conn.address, conn.username.clone(), to, uid)[..], &conn.client).ok()?.text().ok()?;
    let message_de: Message = serde_json::from_str(&message[..]).ok()?;
    let message = dec_prv(&message_de.message_cc.1[..], &conn.sk, &message_de.message_cc.0[..]);
    Some(MessageDe {
        from: conn.username.clone(),
        message: String::from_utf8(message).ok()?,
        timestamp: message_de.timestamp,
        prev: message_de.prev,
        uid: message_de.uid
    })
}

fn get_sent_message_head(conn: &Connection, to: String) -> Option<MessageDe> {
    let data = get_data(&format!("{}/{}/{}/head", conn.address, conn.username.clone(), to)[..], &conn.client).ok()?.text().ok()?;
    let head: Option<UID> = serde_json::from_str(&data[..]).ok()?;
    let head: UID = head?;
    get_sent_message(conn, to, head)
}

fn get_recv_message(conn: &Connection, from: String, uid: UID) -> Option<MessageDe> {
    let message = get_data(&format!("{}/{}/{}/{}", conn.address, from, conn.username.clone(), uid)[..], &conn.client).ok()?.text().ok()?;
    let message_de: Message = serde_json::from_str(&message[..]).ok()?;
    let message = dec_pub(&message_de.message[..], &conn.pkp).ok()?;
    Some(MessageDe {
        from: from.clone(),
        message: String::from_utf8(message).ok()?,
        timestamp: message_de.timestamp,
        prev: message_de.prev,
        uid: message_de.uid
    })
}

fn get_recv_message_head(conn: &Connection, from: String) -> Option<MessageDe> {
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
            uid: uid,
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

fn cmd_client() {
    let mut input = String::new();

    print!("Server address: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut input).unwrap();
    input.pop();
    let address = &input.clone()[..];
    print!("Username: ");
    stdout().flush().unwrap();
    input.clear();
    stdin().read_line(&mut input).unwrap();
    input.pop();
    let username = &input.clone()[..];
    print!("Password: ");
    stdout().flush().unwrap();
    input.clear();
    stdin().read_line(&mut input).unwrap();
    input.pop();
    let password = &input.clone()[..];
    print!("Register? (y/n) ");
    stdout().flush().unwrap();
    input.clear();
    stdin().read_line(&mut input).unwrap();
    input.pop();
    let register = input.remove(0) == 'y';

    let mut conn = Connection::new(address, username, password, register).unwrap();

    print!("Chat partner: ");
    stdout().flush().unwrap();
    input.clear();
    stdin().read_line(&mut input).unwrap();
    input.pop();
    let partner = &input.clone()[..];
    let mut until: Option<UID> = None;
    loop {
        print!("> ");
        stdout().flush().unwrap();
        input.clear();
        stdin().read_line(&mut input).unwrap();
        input.pop();
        if input.eq_ignore_ascii_case(".exit") {
            break;
        } else {
            if !input.is_empty() {
                send_chat_message(&mut conn, &MessageData {
                    to: partner.to_string(),
                    message: input.clone(),
                }).unwrap();
            }
            let messages = Messages::new(&conn, partner.to_string(), until);
            for msg in messages.collect::<Vec<_>>().iter().rev() {
                until = Some(msg.uid);
                println!("{}: {}", msg.from, msg.message);
            }
        }
    }
}

fn gtk_client() {
    let application = Application::new(
        Some("us.kosdt.professorg.synapsis"),
        Default::default(),
    ).expect("failed to initalize GTK application");

    application.connect_activate(|app| {
        let window = ApplicationWindow::new(app);
        window.set_title("Synapsis");
        window.set_default_size(350, 70);

        let button = Button::with_label("Click me!");
        button.connect_clicked(|_| {
            println!("Clicked!");
        });
        window.add(&button);

        window.show_all();
    });

    application.run(&[]);
}

fn main() {
    cmd_client();
    //gtk_client();
}


