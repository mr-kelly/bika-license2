#[cfg(test)]
mod tests {
    use lib::{decrypt, get_private_key};
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use crate::crypto::{encrypt, PUBLIC_KEY};

    /**
     * 从Private Key里获取 Public Key
     */
    fn generate_rsa_public_key_str_from_private_key_str() -> String {
        // 将私钥字符串解析为 private key
        let private_key = get_private_key();

        let new_public_key = private_key.to_public_key();
        return new_public_key.to_public_key_pem(LineEnding::LF).unwrap();
    }

    #[test]
    fn it_works() {
        // 测试pub key正确性
        let result = generate_rsa_public_key_str_from_private_key_str();
        assert_eq!(result, PUBLIC_KEY);

        // 加密、解密
        let encrypted = encrypt("{'abc': 123}").expect("Encryption should succeed");
        let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, "{'abc': 123}");
    }

    #[test]
    fn test_determine_actual_max_length() {
        // 分析公钥的实际参数
        use rsa::pkcs8::DecodePublicKey;
        use rsa::{RsaPublicKey, traits::PublicKeyParts};
        
        let public_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();
        let key_size_bits = public_key.size() * 8; // size() 返回字节数
        let key_size_bytes = public_key.size();
        
        println!("RSA Key size: {} bits ({} bytes)", key_size_bits, key_size_bytes);
        
        // PKCS1v15 填充的理论最大明文长度 = 密钥长度(字节) - 11
        let theoretical_max = key_size_bytes - 11;
        println!("Theoretical max message length: {} bytes", theoretical_max);
        
        // 实际测试不同长度的消息
        for length in (theoretical_max - 5)..=(theoretical_max + 5) {
            let test_message = "A".repeat(length);
            match encrypt(&test_message) {
                Ok(_) => println!("✓ Length {} bytes: SUCCESS", length),
                Err(e) => println!("✗ Length {} bytes: FAILED - {}", length, e),
            }
        }
        
        // 验证理论值是否正确
        assert_eq!(theoretical_max, 245, "Expected 2048-bit RSA key with 245 byte max");
    }

    #[test]
    fn test_encrypt_normal_message() {
        // 测试正常长度的消息
        let message = "This is a normal length message for testing";
        let result = encrypt(message);
        assert!(result.is_ok(), "Normal message should encrypt successfully");
        
        if let Ok(encrypted) = result {
            let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_encrypt_max_length_message() {
        // 测试最大长度的消息 (245 字节)
        let message = "a".repeat(245);
        let result = encrypt(&message);
        assert!(result.is_ok(), "Message at max length should encrypt successfully");
        
        if let Ok(encrypted) = result {
            let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_encrypt_too_long_message() {
        // 测试超过最大长度的消息 (246 字节)
        let message = "a".repeat(246);
        let result = encrypt(&message);
        assert!(result.is_err(), "Message over max length should fail");
        
        if let Err(error) = result {
            assert!(error.contains("Message too long"), "Error should mention message is too long");
            assert!(error.contains("246 bytes"), "Error should mention actual length");
            assert!(error.contains("245 bytes"), "Error should mention max allowed length");
            assert!(error.contains("RSA-2048"), "Error should mention key size");
            assert!(error.contains("PKCS1v15"), "Error should mention padding type");
        }
    }

    #[test]
    fn test_encrypt_empty_message() {
        // 测试空消息
        let message = "";
        let result = encrypt(message);
        assert!(result.is_ok(), "Empty message should encrypt successfully");
        
        if let Ok(encrypted) = result {
            let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_encrypt_boundary_messages() {
        // 测试边界附近的消息长度
        for len in [243, 244, 245, 246, 247] {
            let message = "x".repeat(len);
            let result = encrypt(&message);
            
            if len <= 245 {
                assert!(result.is_ok(), "Message of length {} should succeed", len);
                if let Ok(encrypted) = result {
                    let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
                    assert_eq!(decrypted, message);
                }
            } else {
                assert!(result.is_err(), "Message of length {} should fail", len);
            }
        }
    }
}
