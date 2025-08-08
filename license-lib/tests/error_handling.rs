use base64::prelude::*;
use lib::*;

#[test]
fn test_decrypt_with_invalid_base64() {
  // 测试无效的base64输入应该返回错误
  let result = decrypt("invalid_base64!");
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Invalid base64 encoding"));
}

#[test]
fn test_decrypt_with_invalid_encrypted_data() {
  // 测试有效的base64但无效的加密数据应该返回错误
  let invalid_encrypted = BASE64_STANDARD.encode(b"this is not encrypted data");
  let result = decrypt(&invalid_encrypted);
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Invalid encrypted data size"));
}

#[test]
fn test_decrypt_with_empty_string() {
  // 测试空字符串输入
  let result = decrypt("");
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Input cannot be empty"));
}

#[test]
fn test_decrypt_with_malformed_base64() {
  // 测试格式错误的base64
  let result = decrypt("SGVsbG8gV29ybGQ==="); // 过多的 padding
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("Invalid base64 encoding"));
}
