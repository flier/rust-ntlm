
use failure::Error;
use generic_array::GenericArray;
use time::get_time;

use errors::NtlmError;
use proto::{generate_challenge, oem, AuthenticateMessage, AvId, ChallengeMessage, LmChallengeResponse, NegotiateFlags,
            NegotiateMessage, NtChallengeResponse, NtlmSecurityLevel, Version, utf16};

#[derive(Clone, Debug, Default)]
pub struct NtlmClient {
    /// A string that indicates the name of the user.
    pub username: String,
    /// Password of the user.
    ///
    /// If the password is longer than 14 characters, the LMOWF v1 cannot be computed.
    /// For LMOWF v1, if the password is shorter than 14 characters, it is padded by appending zeroes.
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
    /// NTLM security levels determine the minimum security settings
    /// allowed on a client, server, or DC to authenticate in an NTLM domain.
    pub security_level: NtlmSecurityLevel,
}

impl NtlmClient {
    pub fn start_negotiate(&self) -> NegotiateMessage {
        let mut flags = NegotiateFlags::NTLMSSP_REQUEST_TARGET | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
            | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;

        if self.require_128bit_encryption {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_128;
        }

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
                domain_name: self.domain_name.as_ref().map(|s| oem(s).into()),
                workstation_name: self.workstation_name.as_ref().map(|s| oem(s).into()),
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

        if self.no_lm_response_ntlm_v1
            && !challenge_message
                .flags
                .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        {
            bail!(NtlmError::UnsupportedFunction);
        }

        let support_unicode = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE);

        let flags = NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM | if support_unicode {
            NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE
        } else {
            NegotiateFlags::NTLMSSP_NEGOTIATE_OEM
        };

        let curent_time = challenge_message
            .get(AvId::Timestamp)
            .and_then(|av_pair| av_pair.to_timestamp())
            .unwrap_or_else(|| get_time().into());
        let server_challenge = GenericArray::from_slice(challenge_message.server_challenge.as_ref());

        let (nt_challenge_response, lm_challenge_response) = match self.security_level {
            NtlmSecurityLevel::Level0 | NtlmSecurityLevel::Level1 => if challenge_message
                .flags
                .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
            {
                let client_challenge = generate_challenge();

                (
                    NtChallengeResponse::with_extended_session_security(
                        &self.password,
                        server_challenge,
                        &client_challenge,
                    ),
                    LmChallengeResponse::with_extended_session_security(&client_challenge),
                )
            } else {
                (
                    NtChallengeResponse::v1(&self.password, server_challenge),
                    LmChallengeResponse::v1(&self.password, server_challenge),
                )
            },
            NtlmSecurityLevel::Level2 => {
                let nt_challenge_response = NtChallengeResponse::v1(&self.password, server_challenge);
                let response = nt_challenge_response.as_ref().unwrap().response();

                (
                    nt_challenge_response,
                    Some(LmChallengeResponse::V1 { response }),
                )
            }
            NtlmSecurityLevel::Level3 | NtlmSecurityLevel::Level4 | NtlmSecurityLevel::Level5 => {
                if !challenge_message.contains(AvId::NbComputerName) || !challenge_message.contains(AvId::NbDomainName)
                {
                    bail!(NtlmError::LogonFailure);
                }

                (
                    NtChallengeResponse::v2(
                        &self.username,
                        &self.password,
                        self.domain_name.as_ref().map(|s| s.as_str()),
                        server_challenge,
                        &generate_challenge(),
                        curent_time,
                    ),
                    LmChallengeResponse::v2(
                        &self.username,
                        &self.password,
                        self.domain_name.as_ref().map(|s| s.as_str()),
                        server_challenge,
                        &generate_challenge(),
                    ),
                )
            }
        };

        Ok(AuthenticateMessage {
            flags,
            lm_challenge_response,
            nt_challenge_response,
            domain_name: self.domain_name
                .as_ref()
                .map_or_else(Default::default, |s| {
                    if support_unicode { utf16(s) } else { oem(s) }.into()
                }),
            user_name: if support_unicode {
                utf16(&self.username)
            } else {
                oem(&self.username)
            }.into(),
            workstation_name: self.workstation_name
                .as_ref()
                .map_or_else(Default::default, |s| {
                    if support_unicode { utf16(s) } else { oem(s) }.into()
                }),
            session_key: None,
            version: None,
            mic: None,
        })
    }
}
