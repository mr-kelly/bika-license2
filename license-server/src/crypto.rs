use base64::prelude::*;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, traits::PublicKeyParts, rand_core::OsRng};
use log::info;

// 定义 RSA 公钥（公钥可以多个，通常从私钥生成）
// 公钥用于加密，不放客户端
pub const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8lT2ZEzIope4BlJQEl+4
w5g2sUqyyuwNG/zu/iH/vGcf5tgq1zZmWj0+NztZ3LiYzCZwpbYBEpC6QDDvA9Xp
DBOZ8Loy6lOTYR8vJMeEJ9pycFNkPTVKWzZc2tHvikCNe6ilaa0Gxxl5Qb9vpWtE
ei3WuNBp3GdEdvZJ5q3p98Q47fGqXQLJwJb9HG93CE8Qg8D8oROVlcySD5eIdl1G
fCEdfiTKNgzroPpcB2LjPfa7Fl8azfGUnjuUcXRI20CLlza3L7dA4IKSYph0wgwp
m0tmCyki/8wUbRXW3mVAhJuTHIR60n/WXEylIAKhSq3oqcIwE35SciTws09lGTNi
fwIDAQAB
-----END PUBLIC KEY-----
"#;

fn get_public_key() -> RsaPublicKey {
    RsaPublicKey::from_public_key_pem(PUBLIC_KEY).unwrap()
}

// 动态计算最大消息长度
fn get_max_message_length() -> usize {
    let public_key = get_public_key();
    // PKCS1v15 填充：最大明文长度 = 密钥长度(字节) - 11
    public_key.size() - 11
}

pub fn encrypt(message: &str) -> Result<String, String> {
    println!("Encrypting message: {}", message);

    let max_length = get_max_message_length();
    let public_key = get_public_key();
    
    if message.len() > max_length {
        return Err(format!(
            "Message too long: {} bytes. Maximum allowed: {} bytes (RSA-{} with PKCS1v15 padding)", 
            message.len(), 
            max_length,
            public_key.size() * 8 // 密钥位数
        ));
    }

    info!("This is a log message!7");
    info!("This is a log message!8");
    let mut rng = OsRng;
    
    match public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes()) {
        Ok(encrypted_message) => {
            info!("This is a log message!9");
            Ok(BASE64_STANDARD.encode(encrypted_message))
        },
        Err(e) => {
            Err(format!("Encryption failed: {}", e))
        }
    }
}
