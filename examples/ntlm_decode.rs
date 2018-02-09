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
extern crate time;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::str;

use byteorder::{ByteOrder, LittleEndian};
use getopts::Options;
use hexplay::HexViewBuilder;

use ntlm::NtlmError;
use ntlm::proto::{FromWire, LmChallengeResponse, NegotiateFlags, NtChallengeResponse, NtlmMessage, from_utf16};

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

fn main() {
    let _ = pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();

    let mut opts = Options::new();

    opts.optopt("o", "output", "output to file", "<FILE>");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            error!("fail to parse arguments, {}", err);
            process::exit(-1);
        }
    };

    if matches.opt_present("h") {
        let brief = format!("Usage: {} [options] <base64 encoded NTLM message>", program);
        print!("{}", opts.usage(&brief));
        return;
    }

    let mut output = matches
        .opt_str("o")
        .and_then(|filename| {
            if filename == "-" {
                None
            } else {
                Some(Output::File(File::open(filename).unwrap()))
            }
        })
        .unwrap_or_else(|| Output::Stdout(io::stdout()));

    for s in &matches.free {
        debug!("decoding base64 encoded NTLM message: {}", s);

        let payload = base64::decode(s).unwrap();

        trace!(
            "parsing message:\n{}",
            HexViewBuilder::new(&payload).row_width(16).finish()
        );

        match NtlmMessage::from_wire(&payload) {
            Ok(message) => {
                info!("decoded NTLM message: {:?}", message);

                match message {
                    NtlmMessage::Negotiate(msg) => write!(
                        &mut output,
                        r#"NTLM Negotiate Message:
        Flags: {:?}
       Domain: {}
  Workstation: {}
      Version: {}
"#,
                        msg.flags,
                        msg.domain_name
                            .map(|v| String::from_utf8(v.to_vec()).unwrap())
                            .unwrap_or_default(),
                        msg.workstation_name
                            .map(|v| String::from_utf8(v.to_vec()).unwrap())
                            .unwrap_or_default(),
                        msg.version
                            .map(|version| version.to_string())
                            .unwrap_or_default()
                    ).unwrap(),
                    NtlmMessage::Challenge(msg) => write!(
                        &mut output,
                        r#"NTLM Challenge Message:
            Flags: {:?}
 Server Challenge: 0x{:016X}
      Target Name: {}
      Target Info: {}
          Version: {}
"#,
                        msg.flags,
                        LittleEndian::read_u64(&msg.server_challenge),
                        msg.target_name
                            .map(|v| String::from_utf8(v.to_vec()).unwrap())
                            .unwrap_or_default(),
                        msg.target_info
                            .map(|av_pairs| itertools::join(
                                av_pairs.iter().map(|av_pair| av_pair.to_string()),
                                "\n\t\t   "
                            ))
                            .unwrap_or_default(),
                        msg.version
                            .map(|version| version.to_string())
                            .unwrap_or_default()
                    ).unwrap(),
                    NtlmMessage::Authenticate(msg) => {
                        let support_unicode = msg.flags
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
                            &mut output,
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
                            msg.flags,
                            msg.lm_challenge_response
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
                            msg.nt_challenge_response
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
                            decode_str(&msg.domain_name).unwrap(),
                            decode_str(&msg.user_name).unwrap(),
                            decode_str(&msg.workstation_name).unwrap(),
                            msg.session_key
                                .map(|key| hex::encode(key))
                                .unwrap_or_default(),
                            msg.version
                                .map(|version| version.to_string())
                                .unwrap_or_default(),
                            msg.mic.map(|key| hex::encode(key)).unwrap_or_default(),
                        ).unwrap();
                    }
                }
            }
            Err(err) => error!("fail to decode NTLM message: {}", err),
        }
    }
}
