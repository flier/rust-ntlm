extern crate base64;
extern crate futures;
extern crate getopts;
#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
extern crate ntlm;
extern crate pretty_env_logger;

use std::env;
use std::path::Path;
use std::process;

use futures::future::Future;

use hyper::StatusCode;
use hyper::header::{Authorization, ContentLength};
use hyper::server::{Http, Request, Response, Service};

use getopts::Options;

use ntlm::http::{WWWAuthenticate, NTLM};
use ntlm::proto::WriteTo;
use ntlm::server::NtlmServer;

struct HelloWorld {
    domain: String,
    username: String,
    password: Option<String>,
    server: NtlmServer,
}

const PHRASE: &'static str = "Hello, World!";

impl Service for HelloWorld {
    // boilerplate hooking up hyper's server types
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    // The future representing the eventual Response your call will
    // resolve to. This can change to whatever Future you need.
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        if let Some(auth) = req.headers().get::<Authorization<NTLM>>() {
            debug!("HTTP request with NTLM: {}", auth);

            match self.server.process_message(&auth.message) {
                Ok(Some(message)) => {
                    let mut buf = vec![];

                    match message.write_to(&mut buf) {
                        Ok(_) => Box::new(futures::future::ok(
                            Response::new()
                                .with_status(StatusCode::Unauthorized)
                                .with_header(WWWAuthenticate(vec![
                                    "NTLM".to_owned(),
                                    base64::encode(&buf),
                                ])),
                        )),
                        Err(err) => {
                            warn!("fail to write NTLM message, {}", err);

                            Box::new(futures::future::ok(
                                Response::new().with_status(StatusCode::InternalServerError),
                            ))
                        }
                    }
                }
                Ok(None) => {
                    // We're currently ignoring the Request
                    // And returning an 'ok' Future, which means it's ready
                    // immediately, and build a Response with the 'PHRASE' body.
                    Box::new(futures::future::ok(
                        Response::new()
                            .with_header(ContentLength(PHRASE.len() as u64))
                            .with_body(PHRASE),
                    ))
                }
                Err(err) => {
                    warn!("fail to handle NTLM message, {}", err);

                    Box::new(futures::future::ok(
                        Response::new().with_status(StatusCode::InternalServerError),
                    ))
                }
            }
        } else {
            debug!("HTTP request without NTLM");

            Box::new(futures::future::ok(
                Response::new()
                    .with_status(StatusCode::Unauthorized)
                    .with_header(WWWAuthenticate(vec!["NTLM".to_owned()])),
            ))
        }
    }
}

fn main() {
    let _ = pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();

    let mut opts = Options::new();

    opts.optopt("l", "listen", "listen on the address", "HOST[:PORT]");
    opts.optopt("d", "domain", "server domain", "DOMAIN");
    opts.optopt("u", "user", "user and password", "USER[:PASSWORD]");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            error!("fail to parse arguments, {}", err);
            process::exit(-1);
        }
    };

    if matches.opt_present("h") {
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return;
    }

    let addr = matches
        .opt_str("listen")
        .unwrap_or("127.0.0.1:3000".to_owned())
        .parse()
        .unwrap();

    info!("server listen on {}", addr);

    let domain = matches.opt_str("domain").unwrap_or("localhost".to_owned());
    let (username, password) = if let Some(user) = matches.opt_str("user") {
        if let Some(idx) = user.find(":") {
            (user[..idx].to_owned(), Some(user[idx + 1..].to_owned()))
        } else {
            (user, None)
        }
    } else {
        ("".to_owned(), None)
    };

    let server = Http::new()
        .bind(&addr, move || {
            Ok(HelloWorld {
                domain: domain.clone(),
                username: username.clone(),
                password: password.clone(),
                server: NtlmServer::default(),
            })
        })
        .unwrap();

    server.run().unwrap();
}
