use std::fmt;
use std::str::FromStr;

use hyper::{Error, Result};
use hyper::header::Scheme;

use base64;

use proto::{NegotiateMessage, NtlmMessage, WriteTo};

header! { (WWWAuthenticate, "WWW-Authenticate") => (String)* }

/// Credential holder for NTLM Authentication
#[derive(Clone, Debug, PartialEq)]
pub struct NTLM<'a> {
    pub message: NtlmMessage<'a>,
}

impl<'a> NTLM<'a> {}

impl<'a> Scheme for NTLM<'a> {
    fn scheme() -> Option<&'static str> {
        Some("NTLM")
    }

    fn fmt_scheme(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = vec![];

        self.message.write_to(&mut buf).map_err(|err| {
            warn!("fail to write NTLM message, {}", err);

            fmt::Error
        })?;

        write!(f, "{}", base64::encode(&buf))
    }
}

impl<'a> FromStr for NTLM<'a> {
    type Err = Error;

    fn from_str(s: &str) -> Result<NTLM<'a>> {
        let data = base64::decode(s).map_err(|err| {
            debug!("fail to decode BASE64, {}", err);

            Error::Header
        })?;

        let negotiate_message = NegotiateMessage::parse(&data).map_err(|err| {
            debug!("fail to parse negotiate message, {}", err);

            Error::Header
        })?;

        trace!("received negotiate message: {:?}", negotiate_message);

        Ok(NTLM {
            message: NtlmMessage::Negotiate(negotiate_message.into_owned()),
        })
    }
}
