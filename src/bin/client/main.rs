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
                println!("add: Add friend");
                println!("remove: Remove friend");
                println!("open: Open chat");
                println!("exit: Exit to server list");
                println!("quit: Quit Synapsis");
                print!("> ");
                stdout().flush().unwrap();
                stdin().read_line(&mut input).unwrap();
                input.pop();
                let mut args = input.split_whitespace();
                match args.next() {
                    Some("add") => AddFriend(i),
                    Some("remove") => SelectFriend(i, AfterSelectFriend::Remove),
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
                servers[i].2.push(input.clone());
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
                            to: to,
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


