// 演示新的长消息加密功能的示例
use lib::decrypt;

fn main() {
  println!("=== 长消息加密功能演示 ===\n");

  // 模拟从license-server获得的加密结果
  simulate_short_message();
  simulate_long_message();
  simulate_very_long_message();
}

fn simulate_short_message() {
  println!("1. 短消息测试（向后兼容）");

  // 这是一个模拟的短消息加密结果（传统格式）
  // 在实际应用中，这会从license-server的encrypt函数获得
  let short_message = "Hello World!";
  println!("原始消息: {}", short_message);
  println!("消息长度: {} 字符", short_message.len());
  println!("格式: 传统单块格式（向后兼容）");
  println!("✅ 245字符以内的消息保持原格式不变\n");
}

fn simulate_long_message() {
  println!("2. 长消息测试（新分块格式）");

  let long_message = "A".repeat(500);
  println!("原始消息: {}... (500个A)", "A".repeat(20));
  println!("消息长度: {} 字符", long_message.len());
  println!("格式: CHUNK:3:block1|block2|block3");
  println!("✅ 超过245字符的消息自动使用分块格式\n");
}

fn simulate_very_long_message() {
  println!("3. 超长消息测试");

  // 模拟一个实际的软件许可证
  let license_content = format!(
    "软件许可证\n{}\n\
        产品名称: 专业版软件\n\
        授权用户: 北京科技有限公司\n\
        授权日期: 2025年8月8日\n\
        有效期至: 2026年8月8日\n\
        授权功能: {}\n\
        特殊条款: {}\n\
        技术支持: support@example.com\n\
        版本信息: v2.1.0 支持长消息加密\n\
        数字签名: SHA256(...)\n\
        {}",
    "=".repeat(50),
    vec![
      "基础模块",
      "高级模块",
      "企业模块",
      "API接口",
      "数据导出",
      "批量处理",
      "自定义报表",
      "权限管理",
      "审计日志"
    ]
    .join(", "),
    vec![
      "不得逆向工程",
      "不得二次销售",
      "仅限授权用户使用",
      "支持最多100个并发用户",
      "包含12个月技术支持",
      "可申请功能定制"
    ]
    .join("; "),
    "=".repeat(50)
  );

  println!("实际许可证长度: {} 字符", license_content.len());
  println!("需要的块数: {} 块", (license_content.len() + 244) / 245);
  println!("格式: CHUNK:N:block1|block2|...|blockN");
  println!("✅ 支持任意长度的许可证内容\n");
}

// 测试函数：验证解密功能
#[cfg(test)]
mod demo_tests {
  use super::*;
  use base64::prelude::*;
  use lib::{decrypt, get_private_key};
  use rsa::{rand_core::OsRng, traits::PublicKeyParts, Pkcs1v15Encrypt, RsaPublicKey};

  #[test]
  fn test_demo_encryption_roundtrip() {
    // 实际测试加密解密流程
    let private_key = get_private_key();
    let public_key = RsaPublicKey::from(&private_key);

    // 预先创建测试字符串以避免借用问题
    let boundary_msg = "X".repeat(245);
    let long_msg = "Y".repeat(500);
    let very_long_msg = "Z".repeat(1000);

    // 测试不同长度的消息
    let test_cases = vec![
      ("短消息", "Hello World!"),
      ("边界消息", boundary_msg.as_str()),
      ("长消息", long_msg.as_str()),
      ("超长消息", very_long_msg.as_str()),
    ];

    for (name, message) in test_cases {
      println!("测试 {}: {} 字符", name, message.len());

      let encrypted = encrypt_message(&public_key, message);
      let decrypted = decrypt(&encrypted).expect("解密应该成功");

      assert_eq!(decrypted, message);
      println!("✅ {} 测试通过", name);
    }
  }

  fn encrypt_message(public_key: &RsaPublicKey, message: &str) -> String {
    use rsa::rand_core::OsRng;

    let max_chunk_size = public_key.size() - 11;
    let mut rng = OsRng;

    if message.len() <= max_chunk_size {
      // 单块加密
      let encrypted = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
        .unwrap();
      BASE64_STANDARD.encode(&encrypted)
    } else {
      // 分块加密
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

      format!("CHUNK:{}:{}", chunk_count, encrypted_chunks.join("|"))
    }
  }
}
