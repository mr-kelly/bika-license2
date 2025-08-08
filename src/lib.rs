#![deny(clippy::all)]

use lib::decrypt as lib_decrypt;

#[macro_use]
extern crate napi_derive;

#[napi]
pub fn sum(a: i32, b: i32) -> i32 {
  a + b
}

#[napi]
pub fn decrypt(encrypted_message: String) -> napi::Result<String> {
  match lib_decrypt(&encrypted_message) {
    Ok(result) => Ok(result),
    Err(error) => Err(napi::Error::from_reason(error)),
  }
}

// 生成license code
// #[napi]
// pub fn generate_license_code(expiration_date: i32) -> String {
//   // let mut rng = rand::thread_rng();
//   // let license_code: String = (0..16)
//   //     .map(|_| rng.gen_range('a'..='z'))
//   //     .collect();

//   // // let mut signatures = Vec::new();
//   // // for private_key in private_keys {
//   // //     let mut signer = Signer::new(MessageDigest::sha256(), private_key).unwrap();
//   // //     signer.update(license_code.as_bytes()).unwrap();
//   // //     let signature = signer.sign_to_vec().unwrap();
//   // //     signatures.push(hex::encode(signature));
//   // // }

//   // // format!("{}-{}", license_code, signatures.join(":"))
//   format!("{}-{}", "test", expiration_date)
// }
