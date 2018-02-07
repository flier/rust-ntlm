use crypto::rc4::Rc4;
use failure::Error;
use generic_array::GenericArray;
use time::get_time;

use errors::NtlmError;
use proto::{generate_challenge, generate_key_exchange_key, generate_random_session_key, generate_seal_key,
            generate_sign_key, oem, AuthenticateMessage, AvId, ChallengeMessage, LmChallengeResponse, NegotiateFlags,
            NegotiateMessage, NtChallengeResponse, NtlmSecurityLevel, SealKey, SessionKey, SignKey, Version,
            generate_session_base_key_v1, generate_session_base_key_v2, rc4, utf16};

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
            | NegotiateFlags::NTLMSSP_NEGOTIATE_56
            | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
            | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;

        if self.require_128bit_encryption {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_128;
        }

        if self.no_lm_response_ntlm_v1 {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
        }

        let (domain_name, workstation_name, version) = if self.version.is_none() {
            if self.domain_name.is_some() {
                flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
            }

            if self.workstation_name.is_some() {
                flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
            }

            (
                self.domain_name.as_ref().map(|s| oem(s).into()),
                self.workstation_name.as_ref().map(|s| oem(s).into()),
                None,
            )
        } else {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;

            (None, None, self.version.clone())
        };

        NegotiateMessage {
            flags,
            domain_name,
            workstation_name,
            version,
        }
    }

    pub fn process_challenge<'a, 'b>(
        &self,
        challenge_message: &ChallengeMessage<'a>,
    ) -> Result<(AuthenticateMessage<'b>, NtlmClientSession), Error> {
        let support_128bit_encryption = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_128);
        let support_extended_session_security = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
        let support_unicode = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE);
        let support_message_sign = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_SIGN);
        let support_key_exchange = challenge_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH);

        if self.require_128bit_encryption && !support_128bit_encryption {
            bail!(NtlmError::UnsupportedFunction(
                NegotiateFlags::NTLMSSP_NEGOTIATE_128
            ));
        }
        if self.no_lm_response_ntlm_v1 && !support_extended_session_security {
            bail!(NtlmError::UnsupportedFunction(
                NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            ));
        }

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
        let mut session_base_key = None;

        let (nt_challenge_response, lm_challenge_response) = match self.security_level {
            NtlmSecurityLevel::Level0 | NtlmSecurityLevel::Level1 => if support_extended_session_security {
                let client_challenge = generate_challenge();
                let nt_challenge_response = NtChallengeResponse::with_extended_session_security(
                    &self.password,
                    server_challenge,
                    &client_challenge,
                );
                let lm_challenge_response = LmChallengeResponse::with_extended_session_security(&client_challenge);

                if support_message_sign {
                    session_base_key = Some(generate_session_base_key_v1(&self.password));
                }

                (nt_challenge_response, lm_challenge_response)
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

                let username = &self.username;
                let password = &self.password;
                let domain_name = self.domain_name.as_ref().map(|s| s.as_str());

                let nt_challenge_response = NtChallengeResponse::v2(
                    username,
                    password,
                    domain_name,
                    server_challenge,
                    &generate_challenge(),
                    curent_time,
                    vec![],
                );
                let lm_challenge_response = LmChallengeResponse::v2(
                    username,
                    password,
                    domain_name,
                    server_challenge,
                    &generate_challenge(),
                );

                if support_message_sign {
                    let nt_proof_str = nt_challenge_response.as_ref().unwrap().response();

                    session_base_key = Some(generate_session_base_key_v2(
                        username,
                        password,
                        self.domain_name.as_ref(),
                        GenericArray::from_slice(nt_proof_str.as_ref()),
                    ));
                }

                (nt_challenge_response, lm_challenge_response)
            }
        };

        let mut encrypted_random_session_key = None;

        let client_session = if let Some(session_base_key) = session_base_key {
            let key_exchange_key = generate_key_exchange_key(
                flags,
                &self.password,
                &session_base_key,
                server_challenge,
                GenericArray::from_slice(&lm_challenge_response.as_ref().unwrap().response().as_ref()[..8]),
            );

            let exported_session_key;

            if support_key_exchange {
                exported_session_key = generate_random_session_key();

                encrypted_random_session_key = Some(rc4(&key_exchange_key, &exported_session_key)?.into());
            } else {
                exported_session_key = key_exchange_key;
            }

            let current_revision = self.version
                .as_ref()
                .map(|version| version.revision)
                .unwrap_or_default();

            let client_signing_key = generate_sign_key(flags, &exported_session_key, false);
            let server_signing_key = generate_sign_key(flags, &exported_session_key, true);
            let client_sealing_key = Some(generate_seal_key(
                flags,
                &exported_session_key,
                false,
                current_revision,
            ));
            let server_sealing_key = Some(generate_seal_key(
                flags,
                &exported_session_key,
                true,
                current_revision,
            ));
            let client_handle = client_sealing_key.as_ref().map(|key| Rc4::new(key));
            let server_handle = server_sealing_key.as_ref().map(|key| Rc4::new(key));

            NtlmClientSession {
                exported_session_key,
                client_signing_key,
                server_signing_key,
                client_sealing_key,
                server_sealing_key,
                client_handle,
                server_handle,
            }
        } else {
            NtlmClientSession::default()
        };

        let authenticate_message = AuthenticateMessage {
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
            session_key: encrypted_random_session_key,
            version: self.version.clone(),
            mic: None,
        };

        Ok((authenticate_message, client_session))
    }
}

#[derive(Clone, Default)]
pub struct NtlmClientSession {
    exported_session_key: SessionKey,
    client_signing_key: Option<SignKey>,
    server_signing_key: Option<SignKey>,
    client_sealing_key: Option<SealKey>,
    server_sealing_key: Option<SealKey>,
    client_handle: Option<Rc4>,
    server_handle: Option<Rc4>,
}
