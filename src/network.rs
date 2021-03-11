use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct RegisterData {
    pub username: String,
    pub pkp: String,
    pub pkv: String,
}

#[derive(Serialize, Deserialize)]
pub struct PutData {
    pub data: String,
    pub signature: String,
}

