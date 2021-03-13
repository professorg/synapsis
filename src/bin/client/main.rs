use synapsis::network::{RegisterData, PutData, MessageData, Message};
use synapsis::crypto::{
    gen_pub, enc_pub, PublicKeyPair,
    gen_ver, sign, VerifyKeyPair,
    gen_prv, PrivateKey,
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use reqwest::blocking::{Client, Response};

struct Connection {
    address: String,
    client: Client,
    pkp: PublicKeyPair,
    pkv: VerifyKeyPair,
    sk: PrivateKey,
}

fn send_chat_message(conn: Connection, data: MessageData) -> Result<reqwest::StatusCode, reqwest::StatusCode> {
    let head = get_data(&format!("{}/{}/{}/head", &conn.address[..], data.from, data.to)[..], &conn.client)
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
    let signature = sign(&message[..], &conn.pkv)
        .ok_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;

    let uid = OsRng.next_u64();
    let message = serde_json::to_string(&message)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = Message {
            message: message,
            uid: uid,
            prev: head,
            next: None
        };
    let message = serde_json::to_string(&message)
        .map_err(|_| reqwest::StatusCode::INTERNAL_SERVER_ERROR)?;
    let msg_data = PutData {
        data: message,
        signature: signature,
    };
    put_data(&format!("{}/{}/{}/{}", &conn.address, data.from, data.to, uid)[..], &conn.client, msg_data)
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
    put_data(&format!("{}/{}/{}/head", &conn.address[..], data.from, data.to)[..], &conn.client, uid_data)
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
    let username = "some_user";
    let password = "some_pass";

    let pub_keypair = gen_pub(username, password);
    let pkp = pub_keypair.pubkey();
    let ver_keypair = gen_ver(username, password);
    let pkv = ver_keypair.pubkey();

    let client = reqwest::blocking::Client::new();
    let data = RegisterData {
        username: username.to_string(),
        pkp: pkp,
        pkv: pkv,
    };
    let res = register_keys("http://localhost:8000/register", &client, data)
        .unwrap();
    println!("{:?}", res);

    let message = "This is some data I want to send.".to_string();
    let signature = sign(message.as_bytes(), &ver_keypair).unwrap();
    let data = PutData {
        data: message,
        signature: signature,
    };
    let res = put_data(&format!("http://localhost:8000/{}/{}", username, "my_data").to_string()[..], &client, data)
        .unwrap();
    println!("{:?}", res);

    let res = get_data(&format!("http://localhost:8000/{}/{}", username, "my_data").to_string()[..], &client)
        .unwrap();
    println!("{:?}", res);
    println!("{}", res.text().unwrap());
}

