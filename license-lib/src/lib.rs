use base64::prelude::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use rsa::pkcs8::DecodePrivateKey;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn decrypt(base64_message: &str) -> Result<String, String> {
    // Check input length and validity
    if base64_message.is_empty() {
        return Err("Input cannot be empty".to_string());
    }
    
    // Check if the base64 string is too long 
    // RSA-2048 produces 256-byte ciphertext, which is 344 chars in base64
    // We allow some extra margin for safety
    if base64_message.len() > 400 {
        return Err("Input too long".to_string());
    }

    // Decode base64
    let encrypted_message = match BASE64_STANDARD.decode(base64_message) {
        Ok(data) => data,
        Err(_) => return Err("Invalid base64 encoding".to_string()),
    };

    // Check if the encrypted data has the right size for RSA-2048 (256 bytes)
    if encrypted_message.len() != 256 {
        return Err("Invalid encrypted data size".to_string());
    }

    let private_key = get_private_key();
    let decrypted_message = match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_message) {
        Ok(data) => data,
        Err(_) => return Err("Decryption failed".to_string()),
    };
    
    match String::from_utf8(decrypted_message) {
        Ok(text) => {
            // Check if the decrypted text is too long (should be <= 245 for RSA-2048)
            if text.len() > 245 {
                return Err("Decrypted text too long".to_string());
            }
            Ok(text)
        },
        Err(_) => Err("Invalid UTF-8 in decrypted data".to_string()),
    }
}


/**
 * 获取Private Key 结构体
 */
pub fn get_private_key() -> RsaPrivateKey {
    // 将私钥字符串解析为 private key
    let private_key = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).unwrap();
    return private_key;
}


// 私钥在客户端，用于解密
pub const PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDyVPZkTMiil7gG
UlASX7jDmDaxSrLK7A0b/O7+If+8Zx/m2CrXNmZaPT43O1ncuJjMJnCltgESkLpA
MO8D1ekME5nwujLqU5NhHy8kx4Qn2nJwU2Q9NUpbNlza0e+KQI17qKVprQbHGXlB
v2+la0R6Lda40GncZ0R29knmren3xDjt8apdAsnAlv0cb3cITxCDwPyhE5WVzJIP
l4h2XUZ8IR1+JMo2DOug+lwHYuM99rsWXxrN8ZSeO5RxdEjbQIuXNrcvt0DggpJi
mHTCDCmbS2YLKSL/zBRtFdbeZUCEm5MchHrSf9ZcTKUgAqFKreipwjATflJyJPCz
T2UZM2J/AgMBAAECggEABI1B/4pNrngpFb1QEbhIkSv3wwbDKvqaGG980bszwYcy
WzSuQVKdQ46o74Km4nV5MUR7kzFC/eVIClKg+rJ26SopFxN4R1yAhS9/xDIXMmRx
B9kZJektV19DCT0uQauKvMrjKIP+f5jj5S9CWpoUNDNOODR5+JDcAVwI8VNM9MFq
cMlZw0aNCGhAXGV2/LaPGA628cYpX/+Jl0NcnIWY0GCk1BE/YzVaCouKPjnEHyON
5nwj055xP0+h7hme91FycLA/Ef6kUs2akNLpCenZ9oiZLbMdOysqnYYvpETnEpot
/FcJRFK9YA6nxDiCscF/1CVOpBsnYI5PGdFowq3Z2QKBgQD8GFagF6EnyYE7M/4K
bOYx2QSlYCi5a5E9n7dStcAY8AbJfYMEQ1No05zxUiC9Q6M13uNPnJzv94PKasAP
nOGn4baDmhotU5yjiwS8MHDmF/M+FO3rRjIREBsLaBKfYTqx8up8NpY0bE+V6RrS
GcQ+EmGqFQokdj2ypeTVIcY8VQKBgQD2Fei0C4DDP2V0aWpGGOeO48G/VyWulpj/
bCRygE+J4ySu8QTgQ6z7O6vcuCr+Ea9uVTavlYML2ea8+vGO76zs1MKXWwdHPXji
e8RplIpxzuzoeMUcNyCb3Oq/TkfzzTroioG+sLUUxi6XPyqVHVL7JWLa9s1LXesO
nGMp1tt3gwKBgDaw6QouVi4Vj03Sx8hnO8GQvWtLY0pmxcnCvrjY6WX/nNlVu3jP
SmcxkZjhIm0tIVlsk5AQABQndJYTdrtsY6BSXZBLfGZc/1yTqmFReQzSIVlUnREv
12jQP63H1FJze5Jjiu+LwCZ7YQC647C1GlgFEN8fVWX3qQb66pw6iZFJAoGBAMV3
jTS0qk2CmLnSQSogn+dkUbtlheJUDE+iCpkq5yhhcbVDyELha3RqTJ2f1zfrHxft
HyXEVtTytJne0Gl/YAbnL4Le07dR16f94v1J6dIrVqWxC5J5lhwcKO78NPapL+Uc
B8Lp71TNNuO9F0Fyt3y6YloMg24/3ffqfBQ9yfxbAoGBAI0eGWTFkSztNK0eaFWN
cslTbuOe80DA22c90TVBfg+BsfQbzvGmqCh4Xud3Ud1iwvv4yEnSjWxN0xIpf5ZD
XVFR8vz4ympM/SuOg7/oO41RQtvNCUvwT/dyfhLep7fwsoDGTz6yZIp83eqS9VQm
I6lQDQAVMU3woJGSx67TePxa
-----END PRIVATE KEY-----
"#;

