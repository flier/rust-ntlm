use std::iter::{self, FromIterator};

use crypto::digest::Digest;
use crypto::md5::Md5;
use failure::Error;
use generic_array::GenericArray;
use generic_array::typenum::U8;
use rand::{thread_rng, Rng};
use time::get_time;

use errors::NtlmError;
use proto::{desl, AuthenticateMessage, AvId, ChallengeMessage, LmChallengeResponse, NegotiateFlags, NegotiateMessage,
            NtChallengeResponse, Version, lm_owf_v1, nt_owf_v1};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NtlmClient {
    pub username: String,
    pub password: String,
    /// A domain name or a NetBIOS name that identifies a domain.
    pub domain_name: Option<String>,
    /// The name of the client machine.
    pub workstation_name: Option<String>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
    /// A Boolean setting that controls using the NTLM response for the LM response
    /// to the server challenge when NTLMv1 authentication is used.
    pub no_lm_response_ntlm_v1: bool,
    /// A Boolean setting that requires the client to use 128-bit encryption.
    pub require_128bit_encryption: bool,
}

impl NtlmClient {
    pub fn start_negotiate(&self) -> NegotiateMessage {
        let mut flags = NegotiateFlags::NTLMSSP_REQUEST_TARGET | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
            | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;

        if self.no_lm_response_ntlm_v1 {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        if self.version.is_none() {
            NegotiateMessage {
                flags,
                domain_name: self.domain_name
                    .as_ref()
                    .map(|s| s.as_str().as_bytes().into()),
                workstation_name: self.workstation_name
                    .as_ref()
                    .map(|s| s.as_str().as_bytes().into()),
                version: None,
            }
        } else {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;

            NegotiateMessage {
                flags,
                domain_name: None,
                workstation_name: None,
                version: self.version.clone(),
            }
        }
    }

    pub fn process_challenge<'a, 'b>(
        &self,
        challenge_message: &ChallengeMessage<'a>,
    ) -> Result<AuthenticateMessage<'b>, Error> {
        if self.require_128bit_encryption
            && !challenge_message
                .flags
                .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_128)
        {
            bail!(NtlmError::UnsupportedFunction);
        }

        let curent_time = challenge_message
            .target_info
            .as_ref()
            .and_then(|target_info| {
                target_info
                    .iter()
                    .find(|av_pair| av_pair.id == AvId::Timestamp)
            })
            .and_then(|av_pair| av_pair.to_timestamp())
            .map_or_else(|| get_time(), |ts| ts.into());

        let client_challenge = thread_rng().gen_iter().take(8).collect::<Vec<u8>>();
        let (nt_challenge_response, lm_challenge_response) = self.generate_response(
            self.username.as_str(),
            self.password.as_str(),
            self.domain_name.as_ref().map(|s| s.as_str()),
            challenge_message.flags,
            GenericArray::from_slice(challenge_message.server_challenge.as_ref()),
            GenericArray::from_slice(client_challenge.as_slice()),
        )?;

        unreachable!()
    }

    fn generate_response(
        &self,
        user: &str,
        pass: &str,
        domain: Option<&str>,
        challenge_flags: NegotiateFlags,
        server_challenge: &GenericArray<u8, U8>,
        client_challenge: &GenericArray<u8, U8>,
    ) -> Result<(Option<NtChallengeResponse>, Option<LmChallengeResponse>), Error> {
        let nt_response_key = nt_owf_v1(user, pass, domain);
        let lm_response_key = lm_owf_v1(user, pass, domain);

        if user.is_empty() && pass.is_empty() {
            Ok((None, None))
        } else {
            let nt_challenge_response;
            let lm_challenge_response;

            if challenge_flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
                let mut md5 = Md5::new();

                md5.input(server_challenge.as_slice());
                md5.input(client_challenge.as_slice());

                let mut hash = vec![0; md5.output_bytes()];

                md5.result(&mut hash);

                nt_challenge_response = desl(nt_response_key, GenericArray::from_slice(&hash[..8]));
                lm_challenge_response = GenericArray::from_iter(
                    client_challenge
                        .as_slice()
                        .iter()
                        .cloned()
                        .chain(iter::repeat(0u8))
                        .take(24),
                );
            } else {
                let server_challenge = GenericArray::from_slice(server_challenge.as_ref());

                nt_challenge_response = desl(nt_response_key, server_challenge);
                lm_challenge_response = if self.no_lm_response_ntlm_v1 {
                    nt_challenge_response
                } else {
                    desl(lm_response_key, server_challenge)
                };
            }

            Ok((
                Some(NtChallengeResponse::V1 {
                    response: nt_challenge_response.as_slice().to_vec().into(),
                }),
                Some(LmChallengeResponse::V1 {
                    response: lm_challenge_response.as_slice().to_vec().into(),
                }),
            ))
        }
    }
}
