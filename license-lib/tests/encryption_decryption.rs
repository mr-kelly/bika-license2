use lib::*;
use rsa::{RsaPublicKey, Pkcs1v15Encrypt, rand_core::OsRng};
use base64::prelude::*;

#[test]
fn test_decrypt_with_known_message() {
    // 为了测试解密功能，我们需要先加密一个已知消息
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    
    let original_message = "Hello, World!";
    let original_bytes = original_message.as_bytes();
    
    // 使用公钥加密
    let mut rng = OsRng;
    let encrypted_bytes = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, original_bytes)
        .expect("Failed to encrypt");
    
    // 将加密后的字节转换为base64
    let base64_encrypted = BASE64_STANDARD.encode(&encrypted_bytes);
    
    // 使用我们的解密函数解密
    let decrypted_message = decrypt(&base64_encrypted).expect("Decryption should succeed");
    
    // 验证解密结果
    assert_eq!(decrypted_message, original_message);
}

#[test]
fn test_decrypt_with_different_messages() {
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    let test_messages = vec![
        "Short",
        "A longer message for testing",
        "123456789",
        "Special chars: !@#$%^&*()",
        "Unicode: 你好世界 🌍",
    ];
    
    for original_message in test_messages {
        let original_bytes = original_message.as_bytes();
        
        // 加密
        let encrypted_bytes = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, original_bytes)
            .expect("Failed to encrypt");
        
        let base64_encrypted = BASE64_STANDARD.encode(&encrypted_bytes);
        
        // 解密
        let decrypted_message = decrypt(&base64_encrypted).expect("Decryption should succeed");
        
        // 验证
        assert_eq!(decrypted_message, original_message);
    }
}

#[test]
fn test_end_to_end_encryption_decryption() {
    // 端到端测试：生成公钥，加密，然后解密
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);
    let mut rng = OsRng;
    
    let test_data = "This is a comprehensive end-to-end test of the encryption and decryption process.";
    
    // 加密
    let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, test_data.as_bytes())
        .expect("Encryption failed");
    
    let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
    
    // 解密
    let decrypted = decrypt(&base64_encrypted).expect("Decryption should succeed");
    
    // 验证
    assert_eq!(decrypted, test_data);
}
