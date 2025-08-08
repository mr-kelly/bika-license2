use base64::prelude::*;
use lib::*;
use rsa::{rand_core::OsRng, Pkcs1v15Encrypt, RsaPublicKey};

#[test]
fn test_245_character_boundary() {
  // 测试接近和超过 245 字符限制的情况
  let private_key = get_private_key();
  let public_key = RsaPublicKey::from(&private_key);
  let mut rng = OsRng;

  // 测试 245 字符（应该成功）
  let max_message = "A".repeat(245);
  let encrypted = public_key
    .encrypt(&mut rng, Pkcs1v15Encrypt, max_message.as_bytes())
    .expect("245 chars should encrypt successfully");

  let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
  let decrypted = decrypt(&base64_encrypted).expect("245 chars should decrypt successfully");

  assert_eq!(decrypted, max_message);
  assert_eq!(decrypted.len(), 245);
}

#[test]
fn test_various_message_lengths() {
  // 测试不同长度的消息
  let private_key = get_private_key();
  let public_key = RsaPublicKey::from(&private_key);
  let mut rng = OsRng;

  let test_lengths = vec![1, 10, 50, 100, 150, 200, 244, 245];

  for length in test_lengths {
    let message = "X".repeat(length);

    let encrypted = public_key
      .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
      .expect(&format!("Should encrypt {} chars", length));

    let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
    let decrypted = decrypt(&base64_encrypted).expect(&format!("Should decrypt {} chars", length));

    assert_eq!(decrypted, message);
    assert_eq!(decrypted.len(), length);
  }
}

#[test]
fn test_input_length_validation() {
  // 测试输入长度验证

  // 测试超长输入（超过 400 字符）
  let too_long_input = "A".repeat(450);
  let result = decrypt(&too_long_input);
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Input too long"));
}

#[test]
fn test_encrypted_data_size_validation() {
  // 测试加密数据大小验证

  // 创建错误大小的数据
  let wrong_size_data = vec![0u8; 255]; // 255 字节而不是 256
  let wrong_size_base64 = BASE64_STANDARD.encode(&wrong_size_data);

  let result = decrypt(&wrong_size_base64);
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Invalid encrypted data size"));

  // 测试另一个错误大小
  let another_wrong_size_data = vec![0u8; 257]; // 257 字节
  let another_wrong_size_base64 = BASE64_STANDARD.encode(&another_wrong_size_data);

  let result = decrypt(&another_wrong_size_base64);
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Invalid encrypted data size"));
}

#[test]
fn test_unicode_and_special_characters() {
  // 测试 Unicode 和特殊字符
  let private_key = get_private_key();
  let public_key = RsaPublicKey::from(&private_key);
  let mut rng = OsRng;

  let test_messages = vec![
    "Hello, 世界! 🌍",
    "Émojis: 🚀💻🔐",
    "Math: ∑∏∫√∞",
    "Currency: €£¥₹₿",
    "Arrows: ←→↑↓⟵⟶",
  ];

  for message in test_messages {
    // 确保消息不超过 245 字符
    if message.len() <= 245 {
      let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
        .expect("Should encrypt unicode message");

      let base64_encrypted = BASE64_STANDARD.encode(&encrypted);
      let decrypted = decrypt(&base64_encrypted).expect("Should decrypt unicode message");

      assert_eq!(decrypted, message);
    }
  }
}
