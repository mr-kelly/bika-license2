use lib::*;
use rsa::traits::PublicKeyParts;

#[test]
fn test_get_private_key() {
  let private_key = get_private_key();

  // 验证私钥是否成功解析
  assert_eq!(private_key.size(), 256); // 2048-bit key = 256 bytes

  // 验证私钥的一些基本属性
  assert!(private_key.n().bits() >= 2047); // 应该是2048位密钥
  assert!(private_key.n().bits() <= 2048);
}

#[test]
fn test_private_key_constant() {
  // 验证私钥常量不为空
  assert!(!PRIVATE_KEY.is_empty());

  // 验证私钥格式
  assert!(PRIVATE_KEY.contains("-----BEGIN PRIVATE KEY-----"));
  assert!(PRIVATE_KEY.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn test_private_key_consistency() {
  // 验证多次调用get_private_key()返回相同的密钥
  let key1 = get_private_key();
  let key2 = get_private_key();

  // 比较密钥的n值（模数）
  assert_eq!(key1.n(), key2.n());
  assert_eq!(key1.e(), key2.e());
}
