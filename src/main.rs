use clap::Parser as ClapParser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use std::io::Error as IoError;
use std::path::Path;
use std::sync::Arc;

use async_std::{fs::OpenOptions, io};
use tempfile::TempDir;
use tide::prelude::*;
use tide::{Body, Request, Response, StatusCode};

use handlebars::Handlebars;
use std::collections::BTreeMap;
use tide_handlebars::prelude::*;

/// This program does something useful, but its author needs to edit this.
/// Else it will be just hanging around forever
#[derive(Debug, Clone, ClapParser, Serialize, Deserialize)]
#[clap(version = env!("GIT_VERSION"), author = "Andrew Yourtchenko <ayourtch@gmail.com>")]
struct Opts {
    /// Target hostname to do things on
    #[clap(short, long, default_value = "localhost")]
    target_host: String,

    /// Database path
    #[clap(short)]
    db: String,

    /// Override options from this yaml/json file
    #[clap(short, long)]
    options_override: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
}

enum DbPool {
    Sqlite(sqlx::sqlite::SqlitePool),
    Pg(sqlx::postgres::PgPool),
}

use sqlx::{FromRow, Row};
#[derive(Debug, FromRow, Clone)]
struct ApActor {
    id: i64,
    name: String,
    pubkey: String,
    privkey: String,
}

macro_rules! xdb {
    ($db:ident, $pool:ident, $tree: tt) => {
        match &$db {
            DbPool::Sqlite($pool) => $tree,
            DbPool::Pg($pool) => $tree,
        }
    };
}

#[derive(Clone)]
struct AyTestState {
    tempdir: Arc<TempDir>,
    db: Arc<DbPool>,
    registry: Handlebars<'static>,
}

impl AyTestState {
    fn try_new(db: DbPool) -> Result<Self, IoError> {
        Ok(Self {
            tempdir: Arc::new(tempfile::tempdir()?),
            db: Arc::new(db),
            registry: Handlebars::new(),
        })
    }

    fn path(&self) -> &Path {
        self.tempdir.path()
    }
}

#[derive(Deserialize)]
struct RequestQuery {
    url: String,
}

async fn request_url(mut req: Request<AyTestState>) -> tide::Result {
    let RequestQuery { url } = req.query()?; // .unwrap();
    let mut res: surf::Response = surf::get(url).await?;
    let data: String = res.body_string().await?;

    Ok(data.into())
}

async fn make_user(db: &DbPool, name: &str) {
    use openssl::rsa::{Padding, Rsa};
    use openssl::symm::Cipher;
    println!("Generate user");

    let passphrase = "litir_test";

    let rsa = Rsa::generate(1024).unwrap();
    let private_key: Vec<u8> = rsa
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
        .unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    let privkey = String::from_utf8(private_key).unwrap();
    let pubkey = String::from_utf8(public_key).unwrap();
    println!("Private key: {}", &privkey);
    println!("Public key: {}", &pubkey);

    {
        let newid = xdb!(db, pool, {
            let row: (i64,) = sqlx::query_as(
                "insert into actors (name, pubkey, privkey) values ($1, $2, $3) returning id",
            )
            .bind(name)
            .bind(pubkey.replace("\n", r#"\n"#))
            .bind(privkey.replace("\n", r#"\n"#))
            .fetch_one(pool)
            .await
            .unwrap();
            row.0
        });

        println!("New id: {:?}", newid);
    }
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let opts: Opts = Opts::parse();

    // allow to load the options, so far there is no good built-in way
    let opts = if let Some(fname) = &opts.options_override {
        if let Ok(data) = std::fs::read_to_string(&fname) {
            let res = serde_json::from_str(&data);
            if res.is_ok() {
                res.unwrap()
            } else {
                serde_yaml::from_str(&data).unwrap()
            }
        } else {
            opts
        }
    } else {
        opts
    };

    if opts.verbose > 4 {
        let data = serde_json::to_string_pretty(&opts).unwrap();
        println!("{}", data);
        println!("===========");
        let data = serde_yaml::to_string(&opts).unwrap();
        println!("{}", data);
    }

    println!("Hello, here is your options: {:#?}", &opts);

    use sqlx::Row;
    let db = if opts.db.starts_with("sqlite://") {
        let p = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&opts.db)
            .await
            .unwrap();
        DbPool::Sqlite(p)
    } else if opts.db.starts_with("postgresql://") {
        let p = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&opts.db)
            .await
            .unwrap();
        DbPool::Pg(p)
    } else {
        panic!("Need a database path");
    };
    println!("Connected to a db");

    match &db {
        DbPool::Sqlite(pool) => {
            sqlx::query(
                r#"
CREATE TABLE IF NOT EXISTS actors (
  id integer primary key autoincrement,
  name text,
  pubkey text,
  privkey text
);"#,
            )
            .execute(pool)
            .await
            .unwrap();
        }
        DbPool::Pg(pool) => {
            sqlx::query(
                r#"
CREATE TABLE IF NOT EXISTS actors (
  id bigserial,
  name text,
  pubkey text,
  privkey text
);"#,
            )
            .execute(pool)
            .await
            .unwrap();
        }
    };
    let () = make_user(&db, "testuser").await;

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut state = AyTestState::try_new(db)?;
    let mut app = tide::with_state(state);
    app.at("/request").get(request_url);
    app.listen("127.0.0.1:4000").await?;
    Ok(())
}
