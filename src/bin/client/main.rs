use synapsis::network::RegisterData;
use reqwest::blocking::{Client, Response};

fn register_keys(address: &str, client: Client, data: RegisterData) -> reqwest::Result<Response> {
    client.post(address)
        .json(&data)
        .send()
}

fn main() {
    let data = RegisterData {
        username: "professorg".to_string(),
        pkp: "my_pkp".to_string(),
        pkv: "my_pkv".to_string(),
    };
    let client = reqwest::blocking::Client::new();
    let res = register_keys("http://localhost:8000/register", client, data)
        .unwrap();
    println!("{:?}", res);
}

