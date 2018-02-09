#![recursion_limit = "256"]

extern crate base64;
extern crate byteorder;
extern crate getopts;
extern crate hex;
extern crate hexplay;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate ntlm;
extern crate pretty_env_logger;
extern crate serde_json;
extern crate serde_yaml;
extern crate time;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::str;

use getopts::Options;
use hexplay::HexViewBuilder;

use ntlm::NtlmError;
use ntlm::proto::{AuthenticateMessage, ChallengeMessage, FromWire, LmChallengeResponse, NegotiateFlags,
                  NegotiateMessage, NtChallengeResponse, NtlmMessage, from_utf16};

enum Output {
    Stdout(io::Stdout),
    File(File),
}

impl io::Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Output::Stdout(ref mut stdout) => stdout.write(buf),
            Output::File(ref mut file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Output::Stdout(ref mut stdout) => stdout.flush(),
            Output::File(ref mut file) => file.flush(),
        }
    }
}

impl fmt::Write for Output {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes()).map(|_| ()).map_err(|_| fmt::Error)
    }
}

enum Format {
    Json,
    Yaml,
    Text,
}

impl Format {
    fn dump<W>(&self, writer: &mut W, messages: Vec<NtlmMessage>) -> io::Result<()>
    where
        W: Write,
    {
        match *self {
            Format::Json => {
                serde_json::to_writer(writer, &messages).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            }
            Format::Yaml => {
                serde_yaml::to_writer(writer, &messages).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            }
            Format::Text => {
                for message in messages {
                    self.dump_message(writer, message)?;
                }

                Ok(())
            }
        }
    }

    fn dump_message<W>(&self, writer: &mut W, message: NtlmMessage) -> io::Result<()>
    where
        W: Write,
    {
        match message {
            NtlmMessage::Negotiate(msg) => self.dump_negotiate_message(writer, msg),
            NtlmMessage::Challenge(msg) => self.dump_challenge_message(writer, msg),
            NtlmMessage::Authenticate(msg) => self.dump_authenticate_message(writer, msg),
        }
    }

    fn dump_negotiate_message<W>(&self, writer: &mut W, message: NegotiateMessage) -> io::Result<()>
    where
        W: Write,
    {
        write!(
            writer,
            r#"NTLM Negotiate Message:
         Flags: {:?}
        Domain: {}
   Workstation: {}
       Version: {}
"#,
            message.flags,
            message
                .domain_name
                .map(|v| String::from_utf8(v.to_vec()).unwrap())
                .unwrap_or_default(),
            message
                .workstation_name
                .map(|v| String::from_utf8(v.to_vec()).unwrap())
                .unwrap_or_default(),
            message
                .version
                .map(|version| version.to_string())
                .unwrap_or_default()
        )
    }

    fn dump_challenge_message<W>(&self, writer: &mut W, message: ChallengeMessage) -> io::Result<()>
    where
        W: Write,
    {
        write!(
            writer,
            r#"NTLM Challenge Message:
            Flags: {:?}
 Server Challenge: {}
      Target Name: {}
      Target Info: {}
          Version: {}
"#,
            message.flags,
            hex::encode(message.server_challenge),
            message
                .target_name
                .map(|v| String::from_utf8(v.to_vec()).unwrap())
                .unwrap_or_default(),
            message
                .target_info
                .map(|av_pairs| itertools::join(
                    av_pairs.iter().map(|av_pair| av_pair.to_string()),
                    "\n\t\t   "
                ))
                .unwrap_or_default(),
            message
                .version
                .map(|version| version.to_string())
                .unwrap_or_default()
        )
    }

    fn dump_authenticate_message<W>(&self, writer: &mut W, message: AuthenticateMessage) -> io::Result<()>
    where
        W: Write,
    {
        let support_unicode = message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE);
        let decode_str = |buf| {
            if support_unicode {
                from_utf16(buf)
            } else {
                str::from_utf8(buf)
                    .map(|s| s.to_owned())
                    .map_err(|err| NtlmError::from(err).into())
            }
        };

        write!(
            writer,
            r#"NTLM Authenticate Message
            Flags: {:?}
      LM Response: {}
      NT Response: {}
      Domain Name: {}
        User Name: {}
 Workstation Name: {}
      Session Key: {}
          Version: {}
              MIC: {}
"#,
            message.flags,
            message
                .lm_challenge_response
                .map(|lm_challenge_response| match lm_challenge_response {
                    LmChallengeResponse::V1 { response } => hex::encode(response),
                    LmChallengeResponse::V2 {
                        response,
                        challenge,
                    } => format!(
                        "{}, Challenge: {}",
                        hex::encode(response),
                        hex::encode(challenge)
                    ),
                })
                .unwrap_or_default(),
            message
                .nt_challenge_response
                .map(|nt_challenge_response| match nt_challenge_response {
                    NtChallengeResponse::V1 { response } => hex::encode(response),
                    NtChallengeResponse::V2 {
                        response,
                        challenge,
                    } => format!(
                        r#"{}
        Challenge:
          Timestamp: {}
   Client Challenge: {}
        Target Info: {}"#,
                        hex::encode(response),
                        time::at_utc(challenge.timestamp.into()).ctime(),
                        hex::encode(challenge.challenge_from_client),
                        itertools::join(
                            challenge
                                .target_info
                                .iter()
                                .map(|av_pair| av_pair.to_string()),
                            "\n\t\t     "
                        )
                    ),
                })
                .unwrap_or_default(),
            decode_str(&message.domain_name).unwrap(),
            decode_str(&message.user_name).unwrap(),
            decode_str(&message.workstation_name).unwrap(),
            message
                .session_key
                .map(|key| hex::encode(key))
                .unwrap_or_default(),
            message
                .version
                .map(|version| version.to_string())
                .unwrap_or_default(),
            message.mic.map(|key| hex::encode(key)).unwrap_or_default(),
        )
    }
}

fn main() {
    let _ = pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();

    let mut opts = Options::new();

    opts.optopt("o", "output", "output to file", "<FILE>");
    opts.optflag("", "json", "dump in JSON format");
    opts.optflag("", "yaml", "dump in YAML format");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            error!("fail to parse arguments, {}", err);
            process::exit(-1);
        }
    };

    if matches.opt_present("help") {
        let brief = format!("Usage: {} [options] <base64 encoded NTLM message>", program);
        print!("{}", opts.usage(&brief));
        return;
    }

    let mut output = matches
        .opt_str("output")
        .and_then(|filename| {
            if filename == "-" {
                None
            } else {
                Some(Output::File(File::open(filename).unwrap()))
            }
        })
        .unwrap_or_else(|| Output::Stdout(io::stdout()));

    let format = if matches.opt_present("json") {
        Format::Json
    } else if matches.opt_present("yaml") {
        Format::Yaml
    } else {
        Format::Text
    };

    let messages = matches
        .free
        .into_iter()
        .flat_map(|s| {
            debug!("decoding base64 encoded NTLM message: {}", s);

            base64::decode(&s)
        })
        .collect::<Vec<Vec<u8>>>();

    let messages = messages
        .iter()
        .map(|payload| {
            trace!(
                "parsing message:\n{}",
                HexViewBuilder::new(payload).row_width(16).finish()
            );

            NtlmMessage::from_wire(payload)
        })
        .collect::<Result<Vec<NtlmMessage>, _>>()
        .unwrap();

    format.dump(&mut output, messages).unwrap();
}
