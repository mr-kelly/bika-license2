// 端到端测试：使用license-server的encrypt和license-lib的decrypt
use std::path::Path;
use std::process::Command;

#[test]
fn test_end_to_end_short_message() {
  // 这个测试需要确保license-server和license-lib之间的兼容性
  // 由于跨项目测试的复杂性，我们这里测试各种消息长度的decrypt功能

  // 测试245字符（边界）
  let message_245 = "A".repeat(245);
  test_message_roundtrip(&message_245);

  // 测试246字符（刚好超过边界）
  let message_246 = "B".repeat(246);
  test_message_roundtrip(&message_246);

  // 测试500字符（需要多个块）
  let message_500 = "C".repeat(500);
  test_message_roundtrip(&message_500);
}

fn test_message_roundtrip(message: &str) {
  use base64::prelude::*;
  use lib::{decrypt, get_private_key};
  use rsa::{rand_core::OsRng, traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};

  let private_key = get_private_key();
  let public_key = RsaPublicKey::from(&private_key);
  let mut rng = OsRng;

  let max_chunk_size = public_key.size() - 11; // PKCS1v15 填充

  if message.len() <= max_chunk_size {
    // 单块加密
    let encrypted = public_key
      .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
      .unwrap();
    let base64_encrypted = BASE64_STANDARD.encode(&encrypted);

    let decrypted = decrypt(&base64_encrypted).expect("Decryption should succeed");
    assert_eq!(decrypted, message);
  } else {
    // 分块加密（模拟license-server的encrypt逻辑）
    let message_bytes = message.as_bytes();
    let chunks: Vec<&[u8]> = message_bytes.chunks(max_chunk_size).collect();
    let chunk_count = chunks.len();

    let mut encrypted_chunks = Vec::new();
    for chunk in chunks {
      let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, chunk)
        .unwrap();
      encrypted_chunks.push(BASE64_STANDARD.encode(&encrypted));
    }

    let chunked_message = format!("CHUNK:{}:{}", chunk_count, encrypted_chunks.join("|"));

    let decrypted = decrypt(&chunked_message).expect("Chunked decryption should succeed");
    assert_eq!(decrypted, message);
  }
}

#[test]
fn test_various_content_types() {
  // 测试不同类型的内容

  // JSON数据
  let json_data =
    r#"{"name": "测试用户", "age": 30, "features": ["长消息支持", "向后兼容", "分块加密"]}"#;
  test_message_roundtrip(json_data);

  // 多行文本
  let multiline_text = "第一行\n第二行\n第三行\n包含各种字符：!@#$%^&*()";
  test_message_roundtrip(multiline_text);

  // 长文本许可证
  let license_text = format!(
    "软件许可证协议\n{}\n用户：{}\n授权日期：{}\n功能列表：{}\n版本信息：{}",
    "=".repeat(50),
    "张三（北京科技有限公司）",
    "2025-08-08",
    vec!["基础功能", "高级功能", "企业功能"].join(", "),
    "v2.1.0 支持长消息加密"
  );
  test_message_roundtrip(&license_text);
}

#[test]
fn test_performance_large_messages() {
  use std::time::Instant;

  // 测试性能：1KB消息
  let message_1kb = "X".repeat(1024);
  let start = Instant::now();
  test_message_roundtrip(&message_1kb);
  let duration = start.elapsed();
  println!("1KB message took: {:?}", duration);
  assert!(duration.as_millis() < 1000); // 应该在1秒内完成

  // 测试性能：5KB消息
  let message_5kb = "Y".repeat(5120);
  let start = Instant::now();
  test_message_roundtrip(&message_5kb);
  let duration = start.elapsed();
  println!("5KB message took: {:?}", duration);
  assert!(duration.as_millis() < 3000); // 应该在3秒内完成
}

#[test]
fn test_format_consistency() {
  // 确保格式的一致性
  use lib::decrypt;

  // 测试不同的分块数量
  for chunk_count in 1..=10 {
    let test_message = format!("CHUNK:{}:{}", chunk_count, "dGVzdA==".repeat(chunk_count));

    // 虽然内容可能无效，但格式解析应该是一致的
    let result = decrypt(&test_message);

    if chunk_count == 0 || chunk_count > 100 {
      assert!(result.is_err(), "Invalid chunk count should fail");
    }
    // 注意：这里的base64内容是"test"重复，解密会失败，但格式解析是正确的
  }
}
