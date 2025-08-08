use lib::*;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, rand_core::OsRng, traits::PublicKeyParts};
use base64::prelude::*;

#[test]
fn test_chunked_decryption_format() {
    // 创建一个测试用的分块加密消息
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    // 创建两个小消息块
    let chunk1 = "A".repeat(100);
    let chunk2 = "B".repeat(100);
    
    // 分别加密
    let encrypted1 = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk1.as_bytes()).unwrap();
    let encrypted2 = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk2.as_bytes()).unwrap();
    
    // 创建分块格式：CHUNK:2:base64_1|base64_2
    let base64_1 = BASE64_STANDARD.encode(&encrypted1);
    let base64_2 = BASE64_STANDARD.encode(&encrypted2);
    let chunked_message = format!("CHUNK:2:{}|{}", base64_1, base64_2);
    
    // 解密
    let decrypted = decrypt(&chunked_message).expect("Chunked decryption should succeed");
    
    // 验证结果
    let expected = format!("{}{}", chunk1, chunk2);
    assert_eq!(decrypted, expected);
}

#[test]
fn test_single_block_compatibility() {
    // 测试单块消息的向后兼容性
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    let message = "Traditional single block message";
    
    // 使用传统方式加密
    let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes()).unwrap();
    let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
    
    // 解密应该仍然工作
    let decrypted = decrypt(&base64_encrypted).expect("Traditional decryption should work");
    assert_eq!(decrypted, message);
}

#[test]
fn test_chunked_format_validation() {
    // 测试各种无效的分块格式
    assert!(decrypt("CHUNK:").is_err());
    assert!(decrypt("CHUNK:abc:data").is_err());
    assert!(decrypt("CHUNK:0:").is_err());
    assert!(decrypt("CHUNK:101:").is_err()); // 超过最大块数
    assert!(decrypt("CHUNK:2:onlyoneblock").is_err());
    assert!(decrypt("NOTCHUNK:2:block1|block2").is_err());
}

#[test]
fn test_long_message_simulation() {
    // 模拟长消息的分块加密解密
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    // 创建一个600字符的消息（需要3个块）
    let message = "C".repeat(600);
    let max_chunk_size = public_key.size() - 11; // PKCS1v15 填充
    
    // 手动分块
    let chunks: Vec<&str> = message.as_str()
        .as_bytes()
        .chunks(max_chunk_size)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    
    // 加密每个块
    let mut encrypted_blocks = Vec::new();
    for chunk in chunks {
        let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk.as_bytes()).unwrap();
        encrypted_blocks.push(BASE64_STANDARD.encode(&encrypted));
    }
    
    // 构造分块格式
    let chunked_message = format!("CHUNK:{}:{}", encrypted_blocks.len(), encrypted_blocks.join("|"));
    
    // 解密
    let decrypted = decrypt(&chunked_message).expect("Long message decryption should succeed");
    assert_eq!(decrypted, message);
}

#[test]
fn test_empty_chunk_handling() {
    // 测试空块的处理
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    // 加密空字符串
    let encrypted = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, b"").unwrap();
    let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
    
    // 创建单块格式
    let chunked_message = format!("CHUNK:1:{}", base64_encrypted);
    
    // 解密
    let decrypted = decrypt(&chunked_message).expect("Empty chunk should decrypt");
    assert_eq!(decrypted, "");
}

#[test]
fn test_unicode_in_chunks() {
    // 测试Unicode字符的分块处理
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    let chunk1 = "Hello 世界! ";
    let chunk2 = "🌍 测试中文";
    
    let encrypted1 = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk1.as_bytes()).unwrap();
    let encrypted2 = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk2.as_bytes()).unwrap();
    
    let base64_1 = BASE64_STANDARD.encode(&encrypted1);
    let base64_2 = BASE64_STANDARD.encode(&encrypted2);
    let chunked_message = format!("CHUNK:2:{}|{}", base64_1, base64_2);
    
    let decrypted = decrypt(&chunked_message).expect("Unicode chunks should decrypt");
    let expected = format!("{}{}", chunk1, chunk2);
    assert_eq!(decrypted, expected);
}
