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
    fn test_encrypt_long_message_chunked() {
        // 测试超过单块最大长度的消息 (246 字节) - 现在应该成功并使用分块格式
        let message = "a".repeat(246);
        let result = encrypt(&message);
        assert!(result.is_ok(), "Long message should encrypt successfully using chunked format");
        
        if let Ok(encrypted) = result {
            // 长消息应该使用分块格式
            assert!(encrypted.starts_with("CHUNK:"), "Long message should use chunked format");
            
            // 解密验证
            let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
            assert_eq!(decrypted, message);
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
        // 测试边界附近的消息长度 - 现在所有长度都应该成功
        for len in [243, 244, 245, 246, 247] {
            let message = "x".repeat(len);
            let result = encrypt(&message);
            
            assert!(result.is_ok(), "Message of length {} should succeed", len);
            if let Ok(encrypted) = result {
                // 检查格式
                if len <= 245 {
                    assert!(!encrypted.starts_with("CHUNK:"), "Short message (len={}) should use traditional format", len);
                } else {
                    assert!(encrypted.starts_with("CHUNK:"), "Long message (len={}) should use chunked format", len);
                }
                
                let decrypted = decrypt(&encrypted).expect(&format!("Decryption should succeed for length {}", len));
                assert_eq!(decrypted, message);
            }
        }
    }

    #[test]
    fn test_encrypt_very_long_message() {
        // 测试非常长的消息（需要多个块）
        let message = "B".repeat(1000); // 需要5个块
        let result = encrypt(&message);
        assert!(result.is_ok(), "Very long message should encrypt successfully");
        
        if let Ok(encrypted) = result {
            assert!(encrypted.starts_with("CHUNK:"), "Very long message should use chunked format");
            
            // 解析格式验证
            let parts: Vec<&str> = encrypted.splitn(3, ':').collect();
            assert_eq!(parts.len(), 3);
            assert_eq!(parts[0], "CHUNK");
            
            let chunk_count: usize = parts[1].parse().expect("Should be valid number");
            assert_eq!(chunk_count, 5, "1000 chars should need 5 chunks (1000/245=4.08, round up to 5)");
            
            let blocks: Vec<&str> = parts[2].split('|').collect();
            assert_eq!(blocks.len(), chunk_count);
            
            // 解密验证
            let decrypted = decrypt(&encrypted).expect("Decryption should succeed");
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_encrypt_unicode_messages() {
        // 测试Unicode字符的加密
        let long_unicode_msg = format!("长Unicode消息: {}", "🎯中文🎯".repeat(100));
        
        let test_cases = vec![
            ("中文测试", "测试中文字符的加密解密"),
            ("emoji_test", "Hello 🌍 World! 测试emoji字符 🚀🎉"),
            ("mixed_content", "Mixed content: English + 中文 + русский + العربية + 🌟"),
            ("long_unicode", long_unicode_msg.as_str()), // 超过245字节
        ];
        
        for (name, message) in test_cases {
            let result = encrypt(message);
            assert!(result.is_ok(), "Unicode message '{}' should encrypt successfully", name);
            
            if let Ok(encrypted) = result {
                let decrypted = decrypt(&encrypted).expect(&format!("Unicode message '{}' should decrypt successfully", name));
                assert_eq!(decrypted, message);
                
                println!("✓ Unicode test '{}': {} bytes -> format: {}", 
                    name, 
                    message.len(), 
                    if encrypted.starts_with("CHUNK:") { "chunked" } else { "single" }
                );
            }
        }
    }

    #[test]
    fn test_encrypt_json_license_data() {
        // 测试实际的许可证JSON数据
        let license_json = r#"{
    "product": "Professional Software License",
    "licensee": "Beijing Tech Co., Ltd",
    "license_key": "PROF-2025-ABCD-EFGH-IJKL",
    "issue_date": "2025-08-08",
    "expiry_date": "2026-08-08",
    "features": [
        "basic_module",
        "advanced_module", 
        "enterprise_module",
        "api_access",
        "data_export",
        "batch_processing",
        "custom_reports",
        "user_management",
        "audit_logs"
    ],
    "limits": {
        "max_users": 100,
        "max_projects": 50,
        "api_calls_per_day": 10000
    },
    "support": {
        "level": "premium",
        "contact": "support@example.com",
        "phone": "+86-123-4567-8890"
    },
    "terms": "This license is non-transferable and expires on the specified date. Reverse engineering is prohibited.",
    "signature": "SHA256:abcdef1234567890..."
}"#;
        
        let result = encrypt(license_json);
        assert!(result.is_ok(), "JSON license data should encrypt successfully");
        
        if let Ok(encrypted) = result {
            // JSON数据比较长，应该使用分块格式
            assert!(encrypted.starts_with("CHUNK:"), "Long JSON should use chunked format");
            
            let decrypted = decrypt(&encrypted).expect("JSON license should decrypt successfully");
            assert_eq!(decrypted, license_json);
            
            println!("✓ JSON license test: {} bytes encrypted using chunked format", license_json.len());
        }
    }

    #[test]
    fn test_encrypt_format_consistency() {
        // 测试加密格式的一致性
        let test_cases = vec![
            (100, false),   // 短消息，应该是单块格式
            (245, false),   // 边界消息，应该是单块格式
            (246, true),    // 刚好超过边界，应该是分块格式
            (500, true),    // 长消息，应该是分块格式
            (1000, true),   // 很长消息，应该是分块格式
        ];
        
        for (length, should_be_chunked) in test_cases {
            let message = "T".repeat(length);
            let result = encrypt(&message);
            assert!(result.is_ok(), "Message of length {} should encrypt", length);
            
            if let Ok(encrypted) = result {
                let is_chunked = encrypted.starts_with("CHUNK:");
                assert_eq!(is_chunked, should_be_chunked, 
                    "Message of length {} should {} chunked format", 
                    length, 
                    if should_be_chunked { "use" } else { "not use" }
                );
                
                // 验证解密
                let decrypted = decrypt(&encrypted).expect(&format!("Message of length {} should decrypt", length));
                assert_eq!(decrypted, message);
            }
        }
    }

    #[test]
    fn test_encrypt_performance() {
        // 测试加密性能
        use std::time::Instant;
        
        let test_sizes = vec![
            (1024, "1KB"),
            (5120, "5KB"),
            (10240, "10KB"),
        ];
        
        for (size, name) in test_sizes {
            let message = "P".repeat(size);
            
            let start = Instant::now();
            let result = encrypt(&message);
            let duration = start.elapsed();
            
            assert!(result.is_ok(), "{} message should encrypt successfully", name);
            
            if let Ok(encrypted) = result {
                let decrypt_start = Instant::now();
                let decrypted = decrypt(&encrypted).expect(&format!("{} message should decrypt", name));
                let decrypt_duration = decrypt_start.elapsed();
                
                assert_eq!(decrypted, message);
                
                println!("✓ Performance test {}: encrypt {}ms, decrypt {}ms", 
                    name, 
                    duration.as_millis(), 
                    decrypt_duration.as_millis()
                );
                
                // 性能要求：加密和解密都应该在合理时间内完成
                assert!(duration.as_millis() < 5000, "{} encryption should complete within 5 seconds", name);
                assert!(decrypt_duration.as_millis() < 3000, "{} decryption should complete within 3 seconds", name);
            }
        }
    }
}
