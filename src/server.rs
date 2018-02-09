use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::iter::FromIterator;
use std::str;

use encoding::{DecoderTrap, Encoding};
use encoding::codec::utf_16::UTF_16LE_ENCODING;
use failure::Error;
use generic_array::GenericArray;
use hostname::get_hostname;
use time::get_time;

use auth::{compute_response, generate_challenge, generate_key_exchange_key, ClientChallenge, LmResponseKey,
           NtChallengeResponse, NtResponseKey, ServerChallenge, lm_owf_v1, nt_owf_v1};
use errors::NtlmError;
use proto::{dns_computer_name, dns_domain_name, dns_tree_name, nb_computer_name, nb_domain_name, oem, timestamp,
            AuthenticateMessage, AvId, ChallengeMessage, NegotiateFlags, NegotiateMessage, NtlmMessage, utf16};

pub trait UserCredential {
    fn username(&self) -> &str;

    fn domain(&self) -> &str;

    fn nt_response_key(&self) -> NtResponseKey;

    fn lm_response_key(&self) -> LmResponseKey;
}

pub trait CredentialProvider {
    type Credential: UserCredential;

    fn find<S: AsRef<str>>(&self, username: S, domain: S) -> Option<&Self::Credential>;
}

#[derive(Clone, Debug, Default)]
pub struct PasswordCredential {
    username: String,
    domain: String,
    nt_response_key: NtResponseKey,
    lm_response_key: LmResponseKey,
}

impl PasswordCredential {
    pub fn new<S: AsRef<str>>(username: S, password: S, domain: S) -> Self {
        PasswordCredential {
            username: username.as_ref().to_owned(),
            domain: domain.as_ref().to_owned(),
            nt_response_key: nt_owf_v1(password.as_ref()),
            lm_response_key: lm_owf_v1(password.as_ref()),
        }
    }
}

impl UserCredential for PasswordCredential {
    fn username(&self) -> &str {
        self.username.as_str()
    }

    fn domain(&self) -> &str {
        self.domain.as_str()
    }

    fn nt_response_key(&self) -> NtResponseKey {
        self.nt_response_key
    }

    fn lm_response_key(&self) -> LmResponseKey {
        self.lm_response_key
    }
}

impl str::FromStr for PasswordCredential {
    type Err = Error;

    fn from_str(user: &str) -> Result<Self, Self::Err> {
        let (domain, user) = if let Some(idx) = user.find('\\') {
            (&user[..idx], &user[idx + 1..])
        } else {
            ("", user)
        };

        let (username, password) = if let Some(idx) = user.find(':') {
            (&user[..idx], &user[idx + 1..])
        } else {
            (user, "")
        };

        Ok(PasswordCredential::new(username, password, domain))
    }
}

impl fmt::Display for PasswordCredential {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.domain.is_empty() {
            write!(f, "{}\\", self.domain)?;
        }

        write!(f, "{}", self.username)
    }
}

#[derive(Clone, Debug, Default)]
pub struct SimpleCredentialProvider<C> {
    users: HashMap<(String, String), C>,
}

impl SimpleCredentialProvider<PasswordCredential> {
    pub fn add_user<S: AsRef<str>>(&mut self, username: S, password: S, domain: S) -> Option<PasswordCredential> {
        self.users.insert(
            (username.as_ref().to_owned(), domain.as_ref().to_owned()),
            PasswordCredential::new(username, password, domain),
        )
    }
}

impl<C> CredentialProvider for SimpleCredentialProvider<C>
where
    C: UserCredential,
{
    type Credential = C;

    fn find<S: AsRef<str>>(&self, username: S, domain: S) -> Option<&Self::Credential> {
        self.users
            .get(&(username.as_ref().to_owned(), domain.as_ref().to_owned()))
    }
}

impl<C> FromIterator<C> for SimpleCredentialProvider<C>
where
    C: UserCredential + fmt::Display,
{
    fn from_iter<T: IntoIterator<Item = C>>(iter: T) -> Self {
        SimpleCredentialProvider {
            users: HashMap::from_iter(iter.into_iter().map(|credential| {
                trace!("add credential: `{}`", credential);
                (
                    (
                        credential.username().to_owned(),
                        credential.domain().to_owned(),
                    ),
                    credential,
                )
            })),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NtlmServer<'a> {
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

    state: RefCell<State<'a>>,
}

impl<'a> Default for NtlmServer<'a> {
    fn default() -> NtlmServer<'a> {
        let hostname = get_hostname();

        NtlmServer {
            dns_domain_name: None,
            dns_forest_name: None,
            dns_machine_name: None,
            nb_domain_name: None,
            nb_machine_name: hostname,
            require_128bit_encryption: true,
            state: RefCell::new(State::Negotiating),
        }
    }
}

#[derive(Clone, Debug)]
enum State<'a> {
    Negotiating,
    Challenging(ChallengeMessage<'a>),
    Authenticated,
}

impl<'a> NtlmServer<'a> {
    pub fn domain_joined(&self) -> bool {
        self.dns_forest_name.is_some()
    }

    pub fn process_message<'b, T>(
        &self,
        message: &NtlmMessage<'b>,
        credential_provider: &T,
    ) -> Result<Option<NtlmMessage<'a>>, Error>
    where
        T: CredentialProvider,
    {
        let (next_state, result) = match (&*self.state.borrow(), message) {
            (&State::Negotiating, &NtlmMessage::Negotiate(ref negotiate_message)) => {
                let challenge_message = self.process_negotiate(negotiate_message)?;

                (
                    State::Challenging(challenge_message.clone()),
                    Some(NtlmMessage::Challenge(challenge_message)),
                )
            }

            (&State::Challenging(ref challenge_message), &NtlmMessage::Authenticate(ref authenticate_message)) => {
                self.process_authenticate(challenge_message, authenticate_message, credential_provider)?;

                (State::Authenticated, None)
            }

            _ => bail!(NtlmError::UnexpectedMessage),
        };

        *self.state.borrow_mut() = next_state;

        Ok(result)
    }

    pub fn process_negotiate<'b>(
        &self,
        negotiate_message: &NegotiateMessage<'b>,
    ) -> Result<ChallengeMessage<'a>, Error> {
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

        let target_name = target_name.map(|target_name| {
            if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE) {
                utf16(target_name)
            } else {
                oem(target_name)
            }.into()
        });

        let mut target_info = vec![timestamp(get_time())];

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
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO;
        }

        Ok(ChallengeMessage {
            flags,
            server_challenge: Cow::from(generate_challenge().as_slice().to_vec()),
            target_name,
            target_info: if target_info.is_empty() {
                None
            } else {
                Some(target_info)
            },
            version: None,
        })
    }

    pub fn process_authenticate<T>(
        &self,
        challenge_message: &ChallengeMessage,
        authenticate_message: &AuthenticateMessage,
        credential_provider: &T,
    ) -> Result<(), Error>
    where
        T: CredentialProvider,
    {
        let support_extended_session_security = authenticate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
        let support_unicode = authenticate_message
            .flags
            .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE);

        let null_session = authenticate_message.user_name.is_empty()
            && (authenticate_message.nt_challenge_response.is_none()
                || authenticate_message.lm_challenge_response.is_none());

        if !null_session {
            let challenge_from_client = if let Some(NtChallengeResponse::V2 { ref challenge, .. }) =
                authenticate_message.nt_challenge_response
            {
                Some(challenge.challenge_from_client.clone())
            } else if support_extended_session_security {
                authenticate_message
                    .lm_challenge_response
                    .as_ref()
                    .map(|lm_challenge_response| (&lm_challenge_response.response()[..8]).to_vec().into())
            } else {
                None
            };

            let decode_str = |v: &[u8]| {
                if support_unicode {
                    UTF_16LE_ENCODING
                        .decode(v, DecoderTrap::Ignore)
                        .map_err(|_| NtlmError::Utf16Error)
                } else {
                    str::from_utf8(v)
                        .map(|s| s.to_owned())
                        .map_err(NtlmError::from)
                }
            };

            if let (Some(user), Some(challenge_from_client)) = (
                credential_provider.find(
                    decode_str(authenticate_message.user_name.as_ref())?,
                    decode_str(authenticate_message.domain_name.as_ref())?,
                ),
                challenge_from_client,
            ) {
                let nt_response_key = user.nt_response_key();
                let lm_response_key = user.lm_response_key();

                let server_challenge = ServerChallenge::from_slice(&challenge_message.server_challenge);
                let (expected_nt_challenge_response, expected_lm_challenge_response, expected_session_base_key) =
                    compute_response(
                        authenticate_message.flags,
                        &nt_response_key,
                        &lm_response_key,
                        server_challenge,
                        ClientChallenge::from_slice(&challenge_from_client),
                        challenge_message
                            .get(AvId::Timestamp)
                            .and_then(|av_pair| av_pair.to_timestamp())
                            .unwrap_or_else(|| get_time().into()),
                        challenge_message.target_info.as_ref().unwrap().clone(),
                    );

                let key_exchange_key = generate_key_exchange_key(
                    authenticate_message.flags,
                    &lm_response_key,
                    &expected_session_base_key,
                    server_challenge,
                    GenericArray::from_slice(&expected_lm_challenge_response.response().as_ref()[..8]),
                );
            } else {
                bail!(NtlmError::LogonFailure)
            }
        }

        Ok(())
    }
}
