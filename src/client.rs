use failure::Error;
use time::get_time;

use errors::NtlmError;
use proto::{AuthenticateMessage, AvId, ChallengeMessage, NegotiateFlags, NegotiateMessage, Version};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NtlmClient {
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

        unreachable!()
    }
}
