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

    /// Override options from this yaml/json file
    #[clap(short, long)]
    options_override: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
}

#[derive(Clone)]
struct AyTestState {
    tempdir: Arc<TempDir>,
    registry: Handlebars<'static>,
}

impl AyTestState {
    fn try_new() -> Result<Self, IoError> {
        Ok(Self {
            tempdir: Arc::new(tempfile::tempdir()?),
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

    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut state = AyTestState::try_new()?;
    let mut app = tide::with_state(state);
    app.at("/request").get(request_url);
    app.listen("127.0.0.1:4000").await?;
    Ok(())
}
