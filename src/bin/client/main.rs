use std::collections::HashMap;
use ed25519_dalek::Signature;
use synapsis::{
    crypto::{
        dec_prv, dec_pub, enc_prv, enc_pub, gen_prv, gen_pub, gen_ver, sign, PrivateKey, PublicKeyPair, VerifyKeyPair
    }, network::{Message, MessageData, PutData, RegisterData, UserVerification, UID}
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::blocking::{Client, Response};
use std::{
    fs,
    io::{stdin, stdout, Write},
    time::{SystemTime, Duration, UNIX_EPOCH},
};


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
            sk,
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
            conn,
            with,
            sent,
            recv,
            until,
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
    let head = serde_json::from_str(&data[..]);
    //println!("get_sent_message_head: {:#?}", head);
    let head: Option<UID> = head.ok()?;
    let head: UID = head?;
    get_sent_message(conn, to, head)
}

fn get_recv_message(conn: &Connection, from: String, uid: UID) -> Option<MessageDe> {
    let message = get_data(&format!("{}/{}/{}/{}", conn.address, from, conn.username.clone(), uid)[..], &conn.client);
    //println!("get_recv_message: {:#?}", message);
    let message = message.ok()?.text().ok()?;
    //println!("get_recv_message (ok): {:#?}", message);
    let message_de: Message = serde_json::from_str(&message[..]).ok()?;
    let message = dec_pub(&message_de.message[..], &conn.pkp);
    //println!("get_recv_message (dec): {:#?}", message);
    let message = message.ok()?;
    let message = String::from_utf8(message);
    //println!("get_recv_message (from_utf8): {:#?}", message);
    let message = message.ok()?;
    Some(MessageDe {
        from: from.clone(),
        message,
        timestamp: message_de.timestamp,
        prev: message_de.prev,
        uid: message_de.uid
    })
}

fn get_recv_message_head(conn: &Connection, from: String) -> Option<MessageDe> {
    let data = get_data(&format!("{}/{}/{}/head", conn.address, from, conn.username.clone())[..], &conn.client).ok()?.text().ok()?;
    let head = serde_json::from_str(&data[..]);
    //println!("get_recv_message_head: {:#?}", head);
    let head: Option<UID> = head.ok()?;
    let head: UID = head?;
    get_recv_message(conn, from, head)
}

fn get_pkp(conn: &Connection, to: &String) -> Option<PublicKeyPair> {
  let pkp =
    get_data(&format!("{}/{}/pkp", &conn.address[..], to.clone())[..], &conn.client) 
      .ok()
      .filter(|res| res.status().is_success())
      .and_then(|res| res.text().ok())
      .and_then(|pkp|
        serde_json::from_str::<PublicKeyPair>(&pkp[..])
          .ok());
  pkp
}

fn send_chat_message(conn: &Connection, data: &MessageData) -> Result<reqwest::StatusCode, reqwest::StatusCode> {
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
    let pkp =
      get_pkp(conn, &data.to)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = enc_pub(data.message.as_bytes(), &pkp);
    let message_cc = enc_prv(data.message.as_bytes(), &conn.sk);
    let uid: UID = OsRng.next_u64();
    let timestamp = (SystemTime::now().duration_since(UNIX_EPOCH)).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = Message {
            message,
            message_cc,
            timestamp,
            prev: head,
            uid,
        };
    //let message = serde_json::to_string(&message)
    //    .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let message_val = serde_json::json!(message);
    let message_str = serde_json::ser::to_string(&message_val).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature = sign(&message_str.as_bytes()[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;

    let msg_data = PutData {
        data: message_val,
        signature,
    };
    put_data(&format!("{}/{}/{}/{}", &conn.address, conn.username, data.to, uid)[..], &conn.client, msg_data)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        .and_then(|res|
            if res.status().is_success() {
                Ok(res.status())
            } else {
                Err(res.status())
            })?;

    let uid_val = serde_json::json!(uid);
    let uid_str = serde_json::ser::to_string(&uid_val).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature = sign(&uid_str.as_bytes()[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let uid_data = PutData {
        data: uid_val,
        signature,
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

fn redact_chat_message(conn: &Connection, to: &String, uid: u64) -> Result<(), String> {
  let message_orig: MessageDe = get_sent_message(conn, to.clone(), uid).ok_or("Not found")?;
  let message_redacted = MessageDe {
    message: "[deleted message]".to_string(),
    ..message_orig
  };
  let pkp =
    get_pkp(conn, to)
      .ok_or("Failed to get public key")?;
  let message = enc_pub(message_redacted.message.as_bytes(), &pkp);
  let message_cc = enc_prv(message_redacted.message.as_bytes(), &conn.sk);
  let uid: UID = message_redacted.uid;
  let timestamp = message_redacted.timestamp;
  let prev = message_redacted.prev;
  let message = Message {
          message,
          message_cc,
          timestamp,
          prev,
          uid,
      };
  let message_val = serde_json::json!(message);
  let message_str = serde_json::ser::to_string(&message_val).map_err(|_| "Failed to serialize message")?;
  let signature = sign(&message_str.as_bytes()[..], &conn.pkv)
      .ok_or("Failed to sign message")?;

  let msg_data = PutData {
      data: message_val,
      signature,
  };
  put_data(&format!("{}/{}/{}/{}", &conn.address, conn.username, to, uid)[..], &conn.client, msg_data)
    .map_err(|_| "Failed to update redacted message")?;
  Ok(())
}

fn delete_chat_message_simple(conn: &Connection, to: &String, uid: u64) -> Result<(), String> {
  let path = format!("{}/{}", to, uid);
  let sig =
    sign(path.as_bytes(), &conn.pkv)
      .ok_or("Failed to sign path")?;
  delete_path(&format!("{}/{}/{}", &conn.address[..], &conn.username[..], &path[..])[..], &conn.client, sig)
    .map_err(|_| "Failed to delete data")?;
  Ok(())
}

fn get_friends(conn: &Connection) -> Option<Vec<String>> {
  let response = get_data(&format!("{}/{}/friends", &conn.address[..], conn.username), &conn.client);
  let txt = response.ok()?.text().ok()?;
  let friends = serde_json::from_str(&txt[..]).ok()?;
  friends
}

fn put_friends(conn: &Connection, friends: Vec<String>) -> Result<reqwest::StatusCode, reqwest::StatusCode> {
  let friends_val = serde_json::json!(&friends);
  let friends_str = serde_json::ser::to_string(&friends_val).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
  let signature = sign(&friends_str[..].as_bytes()[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
  let data = PutData {
    data: friends_val,
    signature,
  };
  put_data(&format!("{}/{}/friends", &conn.address[..], conn.username), &conn.client, data)
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

fn delete_user(conn: &Connection) -> Result<reqwest::StatusCode, reqwest::StatusCode> {
  let user = conn.username.clone();
  let reg_data = RegisterData {
      username: user.clone(),
      pkp: conn.pkp.pubkey(),
      pkv: conn.pkv.pubkey(),
  };
  let reg_data_str = serde_json::ser::to_string(&reg_data).map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
  let signature = sign(&reg_data_str[..].as_bytes()[..], &conn.pkv)
    .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
  let verif = UserVerification {
    nonce: reg_data,
    signature,
  };
  delete_data(&format!("{}/{}", &conn.address[..], user.clone()), &conn.client, verif)
    .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)
    .and_then(|res|
        if res.status().is_success() {
            Ok(res.status())
        } else {
            Err(res.status())
        })
}

fn delete_chat(conn: &Connection, with: String) -> Result<(), String> {
  let messages = Messages::new(conn, with.clone(), None);
  let res = messages
    .map(|m| m.uid)
    .map(|uid| delete_chat_message_simple(conn, &with.clone(), uid))
    .reduce(|acc, e| acc.and(e));
  match res {
    None => Ok(()),
    Some(res) => res,
  }
    
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

fn delete_data(address: &str, client: &Client, data: UserVerification) -> reqwest::Result<Response> {
    client.delete(address)
        .json(&data)
        .send()
}

fn delete_path(address: &str, client: &Client, data: Signature) -> reqwest::Result<Response> {
    client.delete(address)
        .json(&data)
        .send()
}

enum ReadState {
    ServerList,
    SelectFile(AfterSelectFile),
    Save(String),
    Load(String),
    AddServer,
    SelectServer(AfterSelectServer),
    Login(usize),
    RemoveServer(usize),
    FriendList(usize),
    AddFriend(usize),
    SelectFriend(usize, AfterSelectFriend),
    RemoveFriend(usize, usize),
    GetFriends(usize),
    DownloadChats(usize),
    RedactChat(usize, usize),
    DeleteChat(usize, usize),
    DeleteAccount(usize),
    Chat(usize, usize, Option<UID>),
}

enum AfterSelectFile {
    Save,
    Load,
}

enum AfterSelectServer {
    Login,
    Remove,
    Connect,
}

enum AfterSelectFriend {
    Remove,
    Open,
    Redact,
    Delete,
}

fn cmd_client() {
    use ReadState::*;

    let mut input = String::new();
    let mut servers: Vec<(String, Option<Connection>, Vec<String>)> = Vec::new();
    let mut state = ReadState::ServerList;
    loop {
        input.clear();
        state = match state {
            ServerList => {
                println!("add: Add server");
                println!("save: Save server list to file");
                println!("load: Load server list from file");
                println!("login: Log into server");
                println!("remove: Remove a server");
                println!("connect: Connect to server");
                println!("exit: Quit Synapsis");
                println!("quit: Quit Synapsis");
                print!("> ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut args = input.split_whitespace();
                match args.next() {
                    Some("add") => AddServer,
                    Some("save") => SelectFile(AfterSelectFile::Save),
                    Some("load") => SelectFile(AfterSelectFile::Load),
                    Some("login") => SelectServer(AfterSelectServer::Login),
                    Some("remove") => SelectServer(AfterSelectServer::Remove),
                    Some("connect") => SelectServer(AfterSelectServer::Connect),
                    Some("exit") => break,
                    Some("quit") => break,
                    _ => ServerList
                }
            }
            SelectFile(next_state) => {
                print!("Filename: ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let file = input.clone();
                match next_state {
                    AfterSelectFile::Save => Save(file),
                    AfterSelectFile::Load => Load(file),
                }
            }
            Save(file) => {
                let servers: Vec<(String, Vec<String>)> = servers.iter()
                    .map(|server| (server.0.clone(), server.2.clone()))
                    .collect();
                let servers = serde_json::to_string(&servers);
                match servers {
                    Ok(servers) => {
                        if fs::write(file, servers).is_err() {
                            println!("Failed to save server list");
                        }
                    }
                    Err(_) => {
                        println!("Failed to save server list");
                    }
                }
                ServerList
            }
            Load(file) => {
                let servers_str = fs::read_to_string(file); 
                match servers_str {
                    Ok(servers_str) => {
                        let servers_de  = serde_json::from_str::<Vec<(String, Vec<String>)>>(&servers_str[..]);
                        match servers_de {
                            Ok(servers_de) => {
                                let mut servers_ld: Vec<(String, Option<Connection>, Vec<String>)> = servers_de.iter().cloned()
                                    .map(|(s, f)| (s, None, f))
                                    .collect();
                                servers.append(&mut servers_ld);
                            }
                            Err(_) => {
                                println!("Failed to load server list");
                            }
                        }
                    }
                    Err(_) => {
                        println!("Failed to load server list");
                    }
                }
                ServerList
            }
            AddServer => {
                print!("Server address: ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                servers.push((input.clone(), None, Vec::new()));
                ServerList
            }
            SelectServer(next_state) => {
                println!("Select a server:");
                for (i, server) in servers.iter().enumerate() {
                    if let Some(conn) = &server.1 {
                        println!("{:3} {} ({})", i + 1, server.0, conn.username);
                    } else {
                        println!("{:3} {}", i + 1, server.0);
                    }
                }
                print!("> ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let index = match input.split_whitespace().next() {
                    Some(i) => match i.parse::<usize>() {
                        Ok(i) => {
                            if (1..=servers.len()).contains(&i) {
                                Some(i)
                            } else {
                                println!("Could not select server: index out of range");
                                None
                            }
                        }
                        _ => {
                            println!("Could not select server: index can't be parsed");
                            None
                        }
                    },
                    None => {
                        println!("Could not select server: no index provided");
                        None
                    },
                };
                match (index, next_state) {
                    (Some(i), AfterSelectServer::Login) => Login(i - 1),
                    (Some(i), AfterSelectServer::Remove) => RemoveServer(i - 1),
                    (Some(i), AfterSelectServer::Connect) => FriendList(i - 1),
                    (None, _) => ServerList
                }
            }
            Login(i) => {
                print!("Register? (y/n) ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut chars = input.chars();
                let register = match chars.next() {
                    Some('y') => true,
                    _ => false,
                };

                input.clear();
                print!("Username: ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let username = input.clone();

                input.clear();
                let password = rpassword::prompt_password_stdout("Password: ").unwrap();

                if username.is_empty() || password.is_empty() {
                    println!("Could not login: username and password must be non-empty");
                    ServerList
                } else if register {
                    let confirm = rpassword::prompt_password_stdout("Confirm: ").unwrap();

                    if password == confirm {
                        match Connection::new(&servers[i].0[..], &username[..], &password[..], true) {
                            Ok(conn) => {
                                servers[i].1 = Some(conn);
                                FriendList(i)
                            }
                            Err(_) => {
                                println!("Could not register: connection could not be established");
                                ServerList
                            }
                        }
                    } else {
                        println!("Could not register: passwords don't match");
                        ServerList
                    }
                } else {
                    match Connection::new(&servers[i].0[..], &username[..], &password[..], false) {
                        Ok(conn) => {
                            servers[i].1 = Some(conn);
                            FriendList(i)
                        }
                        Err(_) => {
                            println!("Could not register: connection could not be established");
                            ServerList
                        }
                    }
                }
            }
            RemoveServer(i) => {
                print!("Are you sure you want to remove the server? (y/n) ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut chars = input.chars();
                match chars.next() {
                    Some('y') => {
                        servers.remove(i);
                    }
                    _ => (),
                };
                ServerList
            }
            FriendList(i) => {
                println!("get: Get friends list from server");
                println!("add: Add friend");
                println!("remove: Remove friend");
                println!("download: Download all chats from added friends");
                println!("redact: Redact chat with friend (replace sent messages with placeholder)");
                println!("delete_chat: Delete chat with friend (delete sent messages)");
                println!("delete_account: Delete entire account");
                println!("open: Open chat");
                println!("exit: Exit to server list");
                println!("quit: Quit Synapsis");
                print!("> ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut args = input.split_whitespace();
                match args.next() {
                    Some("get") => GetFriends(i),
                    Some("add") => AddFriend(i),
                    Some("remove") => SelectFriend(i, AfterSelectFriend::Remove),
                    Some("download") => DownloadChats(i),
                    Some("redact") => SelectFriend(i, AfterSelectFriend::Redact),
                    Some("delete_chat") => SelectFriend(i, AfterSelectFriend::Delete),
                    Some("delete_account") => DeleteAccount(i),
                    Some("open") => SelectFriend(i, AfterSelectFriend::Open),
                    Some("exit") => ServerList,
                    Some("quit") => break,
                    _ => FriendList(i)
                }
            }
            AddFriend(i) => {
                print!("Friend username: ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let friend = input.clone();
                servers[i].2.push(friend.clone());
                let conn = servers[i].1.as_ref().unwrap();
                let mut friends = get_friends(conn).unwrap_or(vec![]);
                if !friends.contains(&friend) {
                  friends.push(friend.clone());
                  if put_friends(conn, friends).is_err() {
                    println!("Failed to update friends list on server")
                  }
                }
                FriendList(i)
            }
            SelectFriend(i, next_state) => {
                println!("Select a friend:");
                for (j, friend) in servers[i].2.iter().enumerate() {
                    println!("{:3} {}", j + 1, friend);
                }
                print!("> ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let index = match input.split_whitespace().next() {
                    Some(j) => match j.parse::<usize>() {
                        Ok(j) => {
                            if (1..=servers[i].2.len()).contains(&j) {
                                Some(j)
                            } else {
                                println!("Could not select friend: index out of range");
                                None
                            }
                        }
                        _ => {
                            println!("Could not select friend: index can't be parsed");
                            None
                        }
                    },
                    None => {
                        println!("Could not select friend: no index provided");
                        None
                    },
                };
                match (index, next_state) {
                    (Some(j), AfterSelectFriend::Remove) => RemoveFriend(i, j - 1),
                    (Some(j), AfterSelectFriend::Open) => {
                        println!("/exit: exit to friends list");
                        println!("/quit: quit Synapsis");
                        println!("Leave blank to get new messages.");
                        println!("All other inputs are sent as messages.");
                        Chat(i, j - 1, None)
                    },
                    (Some(j), AfterSelectFriend::Redact) => RedactChat(i, j - 1),
                    (Some(j), AfterSelectFriend::Delete) => DeleteChat(i, j - 1),
                    (None, _) => FriendList(i)
                }
            }
            RemoveFriend(i, j) => {
                print!("Are you sure you want to remove the friend? (y/n) ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut chars = input.chars();
                match chars.next() {
                    Some('y') => {
                        servers[i].2.remove(j);
                    }
                    _ => (),
                };
                FriendList(i)
            }
            GetFriends(i) => {
              let conn = servers[i].1.as_ref().unwrap();
              let friends = get_friends(conn).unwrap_or(vec![]);
              servers[i].2.clear();
              servers[i].2.extend(friends);
              FriendList(i)
            }
            DownloadChats(i) => {
              print!("Filename: ");
              stdout().flush().unwrap();
              stdin().read_line(&mut input).unwrap();
              input.pop();
              let conn = servers[i].1.as_ref();
              let file = input.clone();
              let friends = servers[i].2.iter();
              let friends_messages =
                friends
                  .map(|friend| (friend.clone(), Messages::new(&conn.unwrap(), friend.clone(), None)));
              let chats = 
                friends_messages
                  .map(|(friend, messages)|
                    (
                      friend,
                      messages
                        .map(|msg| (msg.from, msg.message))
                    )
                  );
              let chats =
                chats
                  .map(|(friend, messages)|
                    (
                      friend,
                      messages
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                      )
                  );
              let chats =
                chats
                  .collect::<HashMap<_,_>>();
              if fs::write(file, serde_json::ser::to_string(&chats).unwrap()).is_err() {
                  println!("Failed to download chats from server.")
              }
              
              FriendList(i)
            }
            RedactChat(i, j) => {
              let conn = servers[i].1.as_ref().unwrap();
              let friends = &servers[i].2;
              let friend = &friends[j];
              //TODO: Use separate iterator for only sent messages
              let messages = Messages::new(&conn, friend.clone(), None); 
              for message in messages {
                if message.from == conn.username {
                  let uid = message.uid;
                  let res = redact_chat_message(conn, friend, uid);
                  if let Err(msg) = res {
                    println!("Error while deleting message: {}", msg);
                  }
                }
              }
              FriendList(i) 
            }
            DeleteChat(i, j) => {
              let conn = servers[i].1.as_ref().unwrap();
              let friends = &servers[i].2;
              let friend = &friends[j];
              let res = delete_chat(conn, friend.clone());
              match res {
                Err(s) => println!("{}", s),
                Ok(_) => (),
              }
              FriendList(i) 
            }
            DeleteAccount(i) => {
              let conn = servers[i].1.as_ref().unwrap();
              let res = delete_user(conn);
              if let Err(msg) = res {
                println!("Error while deleting your account: {}", msg);
              }
              ServerList
            }
            Chat(i, j, until) => {
                let mut last: Option<UID> = until;
                print!("> ");
                stdout().flush().unwrap();
                input.clear();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                if input.eq_ignore_ascii_case("/exit") {
                    FriendList(i)
                } else if input.eq_ignore_ascii_case("/quit") {
                    break;
                } else {
                    if !input.is_empty() {
                        let to = servers[i].2[j].clone();
                        let res = send_chat_message(&mut servers[i].1.as_mut().unwrap(), &MessageData {
                            to,
                            message: input.clone(),
                        });
                        if res.is_err() {
                            println!("Failed to send message. User not found.");
                        }
                    }
                    let messages = Messages::new(&servers[i].1.as_ref().unwrap(), servers[i].2[j].clone(), until);
                    for msg in messages.collect::<Vec<_>>().iter().rev() {
                        last = Some(msg.uid);
                        println!("{}: {}", msg.from, msg.message);
                    }
                    Chat(i, j, last)
                }
            }
        };
    }
}

fn main() {
    cmd_client();
}


