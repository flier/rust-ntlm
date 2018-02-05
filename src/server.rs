use std::borrow::Cow;

use encoding::{EncoderTrap, Encoding};
use encoding::codec::utf_16::UTF_16LE_ENCODING;
use failure::Error;
use rand::{thread_rng, Rng};

use errors::NtlmError;
use proto::{dns_computer_name, dns_domain_name, dns_tree_name, eol, nb_computer_name, nb_domain_name,
            AuthenticateMessage, ChallengeMessage, NegotiateFlags, NegotiateMessage, NtlmMessage};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NtlmServer {
    /// The set of server configuration flags (section 2.2.2.5) that specify the full set of capabilities of the server.
    pub default_flags: NegotiateFlags,
    /// A string that indicates the fully qualified domain name (FQDN) of the server's domain.
    pub dns_domain_name: Option<String>,
    /// A string that indicates the FQDN of the server's forest.
    pub dns_forest_name: Option<String>,
    /// A string that indicates the FQDN of the server.
    pub dns_machine_name: Option<String>,
    /// A string that indicates the NetBIOS name of the server's domain.
    pub nb_domain_name: Option<String>,
    /// A string that indicates the NetBIOS machine name of the server.
    pub nb_machine_name: Option<String>,
    /// A Boolean setting that requires the server to use 128-bit encryption.
    pub require_128bit_encryption: bool,
}

impl NtlmServer {
    pub fn domain_joined(&self) -> bool {
        self.dns_forest_name.is_some()
    }

    pub fn process_message<'a, 'b>(&self, message: &'a NtlmMessage<'a>) -> Result<Option<NtlmMessage<'b>>, Error> {
        match *message {
            NtlmMessage::Negotiate(ref negotiate_message) => self.process_negotiate(negotiate_message)
                .map(|challenge_message| Some(NtlmMessage::Challenge(challenge_message))),
            NtlmMessage::Challenge(_) => bail!(NtlmError::UnexpectedMessage),
            NtlmMessage::Authenticate(ref authenticate_message) => self.process_authenticate(authenticate_message)
                .map(|_| None),
        }
    }

    pub fn process_negotiate<'a, 'b>(
        &self,
        negotiate_message: &NegotiateMessage<'a>,
    ) -> Result<ChallengeMessage<'b>, Error> {
        let mut flags = NegotiateFlags::NTLMSSP_REQUEST_TARGET;

        if negotiate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE)
        {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;
        } else if negotiate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_OEM)
        {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_OEM;
        }

        if negotiate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        } else if negotiate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_LM_KEY)
        {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_LM_KEY;
        }

        let target_name;

        if self.domain_joined() {
            target_name = self.nb_domain_name.as_ref();
            flags |= NegotiateFlags::NTLMSSP_TARGET_TYPE_DOMAIN;
        } else {
            target_name = self.nb_machine_name.as_ref();
            flags |= NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER;
        }

        let target_name = if let Some(target_name) = target_name {
            if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE) {
                UTF_16LE_ENCODING
                    .encode(target_name, EncoderTrap::Ignore)
                    .ok()
                    .map(|v| v.into())
            } else {
                Some(target_name.as_bytes().to_owned().into())
            }
        } else {
            None
        };

        let mut target_info = vec![];

        if let Some(ref machine_name) = self.nb_machine_name {
            target_info.push(nb_computer_name(machine_name.as_str()));
        }
        if let Some(ref domain_name) = self.nb_domain_name {
            target_info.push(nb_domain_name(domain_name.as_str()));
        }
        if let Some(ref machine_name) = self.dns_machine_name {
            target_info.push(dns_computer_name(machine_name.as_str()));
        }
        if let Some(ref domain_name) = self.dns_domain_name {
            target_info.push(dns_domain_name(domain_name.as_str()));
        }
        if let Some(ref forest_name) = self.dns_forest_name {
            target_info.push(dns_tree_name(forest_name.as_str()));
        }

        if !target_info.is_empty() {
            target_info.push(eol());
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO;
        }

        Ok(ChallengeMessage {
            flags,
            server_challenge: Cow::from(thread_rng().gen_iter().take(8).collect::<Vec<u8>>()),
            target_name,
            target_info: if target_info.is_empty() {
                None
            } else {
                Some(target_info)
            },
            version: None,
        })
    }

    pub fn process_authenticate(&self, authenticate_message: &AuthenticateMessage) -> Result<(), Error> {
        Ok(())
    }
}
