use serde::{Deserialize, Serialize};
use worker::*;
// use log::{info};

use lib::decrypt;

mod crypto;
use crypto::encrypt;

#[cfg(test)]
mod tests;
macro_rules! log {
    ($($t:tt)*) => (web_sys::console::log_1(&format!($($t)*).into()))
}
// 数据库存档
#[derive(Deserialize, Serialize)]
struct LicenseCode {
  name: String,
  code: String,
  #[allow(non_snake_case)]
  createdAt: String,
  activated: u32,
  // expiredAt: Option<String>,
  // remark: Option<String>,
  // createdBy: Option<String>,
}

// 请求加密body
#[derive(Deserialize, Serialize)]
struct EncryptRequest {
  s: String,
}

// 检查LICENSE_SERVER_ACCESS_KEY是否正确
fn check_access(license_server_access_key: &str) -> bool {
  if license_server_access_key == "WMDkgEGbKHkCFm6KK" {
    return true;
  }
  return false;
}

#[event(fetch, respond_with_errors)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
  let router = Router::new();
  router
    .get_async("/test", |_req, _ctx| async move {
      match encrypt("Hello, World!") {
        Ok(encrypted) => {
          match decrypt(&encrypted) {
            Ok(decrypted) => Response::ok(format!(
              "Encrypted: {}, Decrypted: {}",
              encrypted, decrypted
            )),
            Err(e) => Response::error(&format!("Decryption error: {}", e), 400)
          }
        },
        Err(e) => Response::error(&format!("Encryption error: {}", e), 400)
      }
    })
    // 获取所有code
    .get_async("/:key/licenses/:limit/:offset", |_req, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
        return Response::error("Access Denied", 403);
      }
      let limit = ctx.param("limit").unwrap();
      let offset = ctx.param("offset").unwrap();

      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare("SELECT * FROM LicenseCode LIMIT ?1 OFFSET ?2");
      let query = statement.bind(&[limit.into(), offset.into()])?;
      let result = query.all().await?;
      Response::from_json(&result.results::<LicenseCode>().unwrap())
    })
    // 只负责加密字符串，解密函数在客户端rust lib
    .post_async("/:key/encrypt", |mut req, ctx| async move {
        let key = ctx.param("key").unwrap();
        if !check_access(key) {
          return Response::error("Access Denied", 403);
        }
        let body = req.json::<EncryptRequest>().await?;
        log!("Start encrypt, {}", body.s);
        match encrypt(&body.s) {
          Ok(encrypted) => {
            Response::ok(encrypted)
          },
          Err(e) => {
            Response::error(&format!("Encryption error: {}", e), 400)
          }
        }
      })
    // 新建一个code
    .post_async("/:key/license", |mut req, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
      return Response::error("Access Denied", 403);
      }
      let body = req.json::<LicenseCode>().await?;
      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare(format!(
      "INSERT INTO LicenseCode (name, code, createdAt, activated) VALUES (?1, ?2, ?3, 0)"
      ));
      let query = statement.bind(&[body.name.into(), body.code.into(), body.createdAt.into()])?;
      query.run().await?;
      Response::ok("Success")
    })
    // 更新一个license
    .patch_async("/:key/license", |mut req, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
      return Response::error("Access Denied", 403);
      }
      let body = req.json::<LicenseCode>().await?;
      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare(
      "UPDATE LicenseCode SET code = ?1, activated = ?2, createdAt = ?3 WHERE name = ?4"
      );
      let query = statement.bind(&[
      body.code.into(), 
      body.activated.into(), 
      body.createdAt.into(), 
      body.name.into(), 
      ])?;
      query.run().await?;
      Response::ok("Success")
    })
    // 获取一个code的信息，通过code倒查
    .post_async("/:key/license/code", |mut req, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
        return Response::error("Access Denied", 403);
      }
      let code = req.text().await?;
      // let code = ctx.param("code").unwrap();
      // 解码base64
      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare("SELECT * FROM LicenseCode WHERE code = ?1");
      let query = statement.bind(&[code.into()])?;
      let result = query.first::<LicenseCode>(None).await?;
      match result {
        Some(thing) => {
            Response::from_json(&thing)
        },
        None => Response::error("Not found", 404),
      }
    })
    // 获取一个code的信息，纯粹查看，作用不大
    .get_async("/:key/license/:name", |_, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
        return Response::error("Access Denied", 403);
      }
      let name = ctx.param("name").unwrap();
      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare("SELECT * FROM LicenseCode WHERE name = ?1");
      let query = statement.bind(&[name.into()])?;
      let result = query.first::<LicenseCode>(None).await?;
      match result {
        Some(thing) => {
            Response::from_json(&thing)
        },
        None => Response::error("Not found", 404),
      }
    })
    // 激活code的信息，通常是服务端激活使用，客户传输 LicenseCode 整个JSON进行匹配
    // 这个接口是public的，无需access key
    .post_async("/license/activate", |mut req, ctx| async move {
        // 要求对方要完整构造上来
        let body = req.json::<LicenseCode>().await?;
        let name = body.name;

        let d1 = ctx.env.d1("license-server")?;
        let statement = d1.prepare("SELECT * FROM LicenseCode WHERE name = ?1 AND code = ?2");
        let query = statement.bind(&[name.into(), body.code.into()])?;
        let result = query.first::<LicenseCode>(None).await?;

        match result {
          Some(thing) => {
              // 找到了，校验 activated +1
              let update_statement = d1.prepare("UPDATE LicenseCode SET activated = ?1 WHERE name = ?2");
              let update_query = update_statement.bind(&[(thing.activated + 1).into(), (&thing.name).into()])?;
              update_query.run().await?;
  
              Response::from_json(&thing)
          },
          None => Response::error("Not found", 404),
        }
      })
    // 删除一个code
    .delete_async("/:key/license/:id", |_, ctx| async move {
      let key = ctx.param("key").unwrap();
      if !check_access(key) {
        return Response::error("Access Denied", 403);
      }
      let id = ctx.param("id").unwrap();
      let d1 = ctx.env.d1("license-server")?;
      let statement = d1.prepare("DELETE FROM LicenseCode WHERE name = ?1");
      let query = statement.bind(&[id.into()])?;
      query.run().await?;
      Response::ok("Success")
    })
    .run(req, env)
    .await
}
