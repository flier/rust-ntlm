#![allow(non_upper_case_globals)]

use std::borrow::Cow;

use byteorder::LittleEndian;
use bytes::BufMut;
use failure::Error;
use nom;
use num::FromPrimitive;

use errors::NtlmError;
use errors::ParseError::{MismatchedMsgType, MismatchedSignature};

/// A 16-bit unsigned integer that defines the information type in the Value field.
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum AvId {
    /// Indicates that this is the last AV_PAIR in the list.
    EOL,
    /// The server's NetBIOS computer name.
    NbComputerName,
    /// The server's NetBIOS domain name.
    NbDomainName,
    /// The fully qualified domain name (FQDN) of the computer.
    DnsComputerName,
    /// The FQDN of the domain.
    DnsDomainName,
    /// The FQDN of the forest.
    DnsTreeName,
    /// A 32-bit value indicating server or client configuration.
    Flags,
    /// A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time.
    Timestamp,
    /// A Single_Host_Data (section 2.2.2.2) structure.
    SingleHost,
    /// The SPN of the target server.
    TargetName,
    /// A channel bindings hash.
    ChannelBindings,
}

/// The `AvPair` structure defines an attribute/value pair.
#[derive(Clone, Debug, PartialEq)]
pub struct AvPair<'a> {
    /// A 16-bit unsigned integer that defines the information type in the Value field.
    pub id: AvId,
    /// A variable-length byte-array that contains the value defined for this AV pair entry.
    pub value: Cow<'a, [u8]>,
}

impl<'a> AvPair<'a> {
    pub fn new(id: AvId, value: Cow<'a, [u8]>) -> AvPair<'a> {
        AvPair { id, value }
    }

    pub fn size(&self) -> usize {
        kAvIdSize + kAvLenSize + self.value.as_ref().len()
    }
}

impl<'a> WriteTo for AvPair<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u16::<LittleEndian>(self.id as u16);
        buf.put_u16::<LittleEndian>(self.value.as_ref().len() as u16);
        buf.put_slice(self.value.as_ref());

        Ok(self.size())
    }
}

#[macro_export]
macro_rules! utf16 {
    ($s:expr) => {
        ::encoding::Encoding::encode(
            &::encoding::codec::utf_16::UTF_16LE_ENCODING,
            $s,
            ::encoding::EncoderTrap::Ignore
        ).unwrap().into()
    };
}

pub fn eol<'a>() -> AvPair<'a> {
    AvPair {
        id: AvId::EOL,
        value: Default::default(),
    }
}

pub fn nb_computer_name(computer_name: &str) -> AvPair {
    AvPair {
        id: AvId::NbComputerName,
        value: utf16!(computer_name),
    }
}

pub fn nb_domain_name(domain_name: &str) -> AvPair {
    AvPair {
        id: AvId::NbDomainName,
        value: utf16!(domain_name),
    }
}

pub fn dns_computer_name(computer_name: &str) -> AvPair {
    AvPair {
        id: AvId::DnsComputerName,
        value: utf16!(computer_name),
    }
}

pub fn dns_domain_name(domain_name: &str) -> AvPair {
    AvPair {
        id: AvId::DnsDomainName,
        value: utf16!(domain_name),
    }
}

pub fn dns_tree_name(tree_name: &str) -> AvPair {
    AvPair {
        id: AvId::DnsTreeName,
        value: utf16!(tree_name),
    }
}

pub fn target_name(target_name: &str) -> AvPair {
    AvPair {
        id: AvId::TargetName,
        value: utf16!(target_name),
    }
}

/// The `SingleHostData` structure allows a client to send machine-specific information
/// within an authentication exchange to services on the same machine.
#[derive(Clone, Debug, PartialEq)]
pub struct SingleHostData<'a> {
    /// An 8-byte platform-specific blob containing info only relevant
    /// when the client and the server are on the same host.
    pub custom_data: u64,
    /// A 256-bit random number created at computer startup to identify the calling machine.
    pub machine_id: Cow<'a, [u8]>,
}

bitflags! {
    /// These flags define client or server NTLM capabilities supported by the sender.
    pub struct NegotiateFlags: u32 {
        /// If set, requests Unicode character set encoding.
        const NTLMSSP_NEGOTIATE_UNICODE = 0x0000_0001;
        /// If set, requests OEM character set encoding.
        const NTLM_NEGOTIATE_OEM = 0x0000_0002;
        /// If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied.
        const NTLMSSP_REQUEST_TARGET = 0x0000_0004;
        /// If set, requests session key negotiation for message signatures.
        const NTLMSSP_NEGOTIATE_SIGN = 0x0000_0010;
        /// If set, requests session key negotiation for message confidentiality.
        const NTLMSSP_NEGOTIATE_SEAL = 0x0000_0020;
        /// If set, requests connectionless authentication.
        const NTLMSSP_NEGOTIATE_DATAGRAM = 0x0000_0040;
        /// If set, requests LAN Manager (LM) session key computation.
        const NTLMSSP_NEGOTIATE_LM_KEY = 0x0000_0080;
        /// If set, requests usage of the NTLM v1 session security protocol.
        const NTLMSSP_NEGOTIATE_NTLM = 0x0000_0200;
        /// If set, the connection SHOULD be anonymous.
        const NTLMSSP_NEGOTIATE_ANONYMOUS = 0x0000_0800;
        /// If set, the domain name is provided (section 2.2.1.1).
        const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x0000_1000;
        /// This flag indicates whether the Workstation field is present.
        const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x0000_2000;
        /// If set, requests the presence of a signature block on all messages.
        const NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;
        /// If set, TargetName MUST be a domain name.
        const NTLMSSP_TARGET_TYPE_DOMAIN = 0x0001_0000;
        /// If set, TargetName MUST be a server name.
        const NTLMSSP_TARGET_TYPE_SERVER = 0x0002_0000;
        /// If set, requests usage of the NTLM v2 session security.
        const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x0008_0000;
        /// If set, requests an identify level token.
        const NTLMSSP_NEGOTIATE_IDENTIFY = 0x0010_0000;
        /// If set, requests the usage of the LMOWF.
        const NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;
        /// If set, indicates that the TargetInfo fields
        /// in the `ChallengeMessage` (section 2.2.1.2) are populated.
        const NTLMSSP_NEGOTIATE_TARGET_INFO = 0x0080_0000;
        /// If set, requests the protocol version number.
        const NTLMSSP_NEGOTIATE_VERSION = 0x0200_0000;
        /// If set, requests 128-bit session key negotiation.
        const NTLMSSP_NEGOTIATE_128 = 0x2000_0000;
        /// If set, requests an explicit key exchange.
        const NTLMSSP_NEGOTIATE_KEY_EXCH = 0x4000_0000;
        /// If set, requests 56-bit encryption.
        const NTLMSSP_NEGOTIATE_56 = 0x8000_0000;
    }
}

/// There are 3 types of messages in NTLM.
///
/// The message type is a field in every NTLM message header.
/// See [MS-NLMP] Section 2.2.
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
#[repr(u32)]
pub enum MessageType {
    Negotiate = 0x01,
    Challenge = 0x02,
    Authenticate = 0x03,
}

/// The `Version` structure contains operating system version information that should be ignored.
///
/// This structure is used for debugging purposes only and its value does not affect NTLM message processing.
#[derive(Clone, Debug, PartialEq)]
pub struct Version {
    /// The major version number of the operating system in use.
    pub major: u8,
    /// The minor version number of the operating system in use.
    pub minor: u8,
    /// The build number of the operating system in use.
    pub build: u16,
    /// The current revision of the NTLMSSP in use.
    pub revision: u8,
}

impl WriteTo for Version {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u8(self.major);
        buf.put_u8(self.minor);
        buf.put_u16::<LittleEndian>(self.build);
        buf.put_uint::<LittleEndian>(0, 3);
        buf.put_u8(self.revision);

        Ok(kVersionSize)
    }
}

/// Version 15 of the NTLMSSP is in use.
pub const NTLMSSP_REVISION_W2K3: u8 = 0x0f;

/// The `NegotiateMessage` defines an NTLM Negotiate message that is sent from the client to the server.
///
/// This message allows the client to specify its supported NTLM options to the server.
#[derive(Clone, Debug, PartialEq)]
pub struct NegotiateMessage<'a> {
    /// The client sets flags to indicate options it supports.
    pub flags: NegotiateFlags,
    /// A field containing DomainName information.
    pub domain_name: Option<Cow<'a, [u8]>>,
    /// A field containing WorkstationName information.
    pub workstation_name: Option<Cow<'a, [u8]>>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
}

impl<'a> NegotiateMessage<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<NegotiateMessage<'a>, Error> {
        match parse_negotiate_message(payload) {
            nom::IResult::Done(remaining, (mut msg, domain_name_field, workstation_name_field)) => {
                let offset = payload.len() - remaining.len();

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)
                    && domain_name_field.length > 0
                {
                    msg.domain_name = Some(Cow::from(domain_name_field.extract_data(remaining, offset)?));
                }

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)
                    && workstation_name_field.length > 0
                {
                    msg.workstation_name = Some(Cow::from(workstation_name_field.extract_data(remaining, offset)?));
                }

                Ok(msg)
            }
            nom::IResult::Error(err) => bail!(NtlmError::from(err)),
            nom::IResult::Incomplete(needed) => bail!(NtlmError::from(needed)),
        }
    }
}

impl<'a> WriteTo for NegotiateMessage<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        let mut offset = kSignatureSize + kMesssageTypeSize + kFlagsSize + kFieldSize * 2 + if self.version.is_some() {
            kVersionSize
        } else {
            0
        };

        buf.put_slice(kSignature);
        buf.put_u32::<LittleEndian>(MessageType::Negotiate as u32);

        let mut flags = self.flags;

        if self.domain_name.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED;
        }

        if self.workstation_name.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
        }

        if self.version.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;
        }

        buf.put_u32::<LittleEndian>(flags.bits());

        offset += self.domain_name.write_field(buf, offset)?;
        offset += self.workstation_name.write_field(buf, offset)?;

        if let Some(ref version) = self.version {
            version.write_to(buf)?;
        }

        if let Some(ref domain_name) = self.domain_name {
            buf.put_slice(domain_name.as_ref());
        }

        if let Some(ref workstation_name) = self.workstation_name {
            buf.put_slice(workstation_name.as_ref());
        }

        Ok(offset)
    }
}

/// The `ChallengeMessage` defines an NTLM challenge message
/// that is sent from the server to the client.
///
/// The `ChallengeMessage` is used by the server to challenge the client
/// to prove its identity. For connection-oriented requests,
/// the `ChallengeMessage` generated by the server is in response to
/// the `NegotiateMessage` (section 2.2.1.1) from the client.
#[derive(Clone, Debug, PartialEq)]
pub struct ChallengeMessage<'a> {
    /// The server sets flags to indicate options it supports or,
    /// if there has been a `NegotiateMessage` (section 2.2.1.1),
    /// the choices it has made from the options offered by the client.
    pub flags: NegotiateFlags,
    /// A 64-bit value that contains the NTLM challenge.
    pub server_challenge: u64,
    /// A field containing TargetName information.
    pub target_name: Option<Cow<'a, [u8]>>,
    /// A field containing TargetInfo information.
    pub target_info: Option<Vec<AvPair<'a>>>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
}

impl<'a> ChallengeMessage<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<ChallengeMessage<'a>, Error> {
        match parse_challenge_message(payload) {
            nom::IResult::Done(remaining, (mut msg, target_name_field, target_info_field)) => {
                let offset = payload.len() - remaining.len();

                if msg.flags.intersects(
                    NegotiateFlags::NTLMSSP_REQUEST_TARGET | NegotiateFlags::NTLMSSP_TARGET_TYPE_DOMAIN
                        | NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER,
                ) && target_name_field.length > 0
                {
                    msg.target_name = Some(Cow::from(target_name_field.extract_data(remaining, offset)?));
                }

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO)
                {
                    let target_info = target_info_field.extract_data(remaining, offset)?;

                    msg.target_info = Some(parse_av_pairs(target_info)
                        .to_full_result()
                        .map_err(NtlmError::from)?);
                }

                Ok(msg)
            }
            nom::IResult::Error(err) => bail!(NtlmError::from(err)),
            nom::IResult::Incomplete(needed) => bail!(NtlmError::from(needed)),
        }
    }
}

impl<'a> WriteTo for ChallengeMessage<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        let mut offset = kSignatureSize + kMesssageTypeSize + kFlagsSize + kFieldSize * 2 + kChallengeSize
            + kReservedSize + if self.version.is_some() {
            kVersionSize
        } else {
            0
        };

        buf.put_slice(kSignature);
        buf.put_u32::<LittleEndian>(MessageType::Challenge as u32);

        offset += self.target_name.write_field(buf, offset)?;

        let mut flags = self.flags;

        if self.target_name.is_some()
            && !flags.intersects(
                NegotiateFlags::NTLMSSP_REQUEST_TARGET | NegotiateFlags::NTLMSSP_TARGET_TYPE_DOMAIN
                    | NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER,
            ) {
            flags |= NegotiateFlags::NTLMSSP_REQUEST_TARGET;
        }

        if self.target_info.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO;
        }

        if self.version.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;
        }

        buf.put_u32::<LittleEndian>(flags.bits());

        buf.put_u64::<LittleEndian>(self.server_challenge);
        buf.put_u64::<LittleEndian>(0); // Reserved

        if let Some(ref target_info) = self.target_info {
            let target_info_size = target_info
                .iter()
                .map(|av_pair| kAvIdSize + kAvLenSize + av_pair.value.as_ref().len())
                .sum::<usize>();

            buf.put_u16::<LittleEndian>(target_info_size as u16);
            buf.put_u16::<LittleEndian>(target_info_size as u16);
            buf.put_u32::<LittleEndian>(offset as u32);

            offset += target_info_size;
        } else {
            buf.put_u16::<LittleEndian>(0);
            buf.put_u16::<LittleEndian>(0);
            buf.put_u32::<LittleEndian>(offset as u32);
        }

        if let Some(ref version) = self.version {
            version.write_to(buf)?;
        }

        if let Some(ref target_name) = self.target_name {
            buf.put_slice(target_name.as_ref());
        }

        if let Some(ref target_info) = self.target_info {
            for av_pair in target_info {
                av_pair.write_to(buf)?;
            }
        }

        Ok(offset)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum LmChallengeResponse<'a> {
    V1 {
        response: Cow<'a, [u8]>,
    },
    V2 {
        response: Cow<'a, [u8]>,
        challenge: Cow<'a, [u8]>,
    },
}

impl<'a> WriteField for LmChallengeResponse<'a> {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error> {
        let data_size = match *self {
            LmChallengeResponse::V1 { ref response } => response.len(),
            LmChallengeResponse::V2 {
                ref response,
                ref challenge,
            } => response.len() + challenge.len(),
        };

        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u32::<LittleEndian>(offset as u32);

        Ok(data_size)
    }
}

impl<'a> WriteTo for LmChallengeResponse<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        match *self {
            LmChallengeResponse::V1 { ref response } => {
                buf.put_slice(response);

                Ok(response.len())
            }
            LmChallengeResponse::V2 {
                ref response,
                ref challenge,
            } => {
                buf.put_slice(response);
                buf.put_slice(challenge);

                Ok(response.len() + challenge.len())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NtChallengeResponse<'a> {
    V1 {
        response: Cow<'a, [u8]>,
    },
    V2 {
        response: Cow<'a, [u8]>,
        challenge: NtlmClientChalenge<'a>,
    },
}

impl<'a> WriteField for NtChallengeResponse<'a> {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error> {
        let data_size = match *self {
            NtChallengeResponse::V1 { ref response } => response.len(),
            NtChallengeResponse::V2 {
                ref response,
                ref challenge,
            } => response.len() + challenge.size(),
        };

        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u32::<LittleEndian>(offset as u32);

        Ok(data_size)
    }
}

impl<'a> WriteTo for NtChallengeResponse<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        match *self {
            NtChallengeResponse::V1 { ref response } => {
                buf.put_slice(response);

                Ok(response.len())
            }
            NtChallengeResponse::V2 {
                ref response,
                ref challenge,
            } => {
                buf.put_slice(response);

                let challenge_size = challenge.write_to(buf)?;

                Ok(response.len() + challenge_size)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NtlmClientChalenge<'a> {
    timestamp: u64,
    challenge: Cow<'a, [u8]>,
    context: Vec<AvPair<'a>>,
}

impl<'a> NtlmClientChalenge<'a> {
    pub fn size(&self) -> usize {
        kNtlmClientChalengeHeaderSize + kTimestampSize + self.challenge.len() + 4
            + self.context
                .iter()
                .map(|av_pair| av_pair.size())
                .sum::<usize>()
    }
}

impl<'a> WriteTo for NtlmClientChalenge<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u8(0x01); // RespType
        buf.put_u8(0x01); // HiRespType
        buf.put_u16::<LittleEndian>(0); // Reserved1
        buf.put_u32::<LittleEndian>(0); // Reserved2
        buf.put_u64::<LittleEndian>(self.timestamp);
        buf.put_slice(self.challenge.as_ref());
        buf.put_u32::<LittleEndian>(0); // Reserved3

        for av_pair in &self.context {
            av_pair.write_to(buf)?;
        }

        Ok(self.size())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticateMessage<'a> {
    /// In connectionless mode, a NEGOTIATE structure that contains a set of flags (section 2.2.2.5)
    /// and represents the conclusion of negotiation—the choices the client has made from the options
    /// the server offered in the CHALLENGE_MESSAGE.
    ///
    /// In connection-oriented mode, a NEGOTIATE structure that contains the set of bit flags (section 2.2.2.5)
    /// negotiated in the previous messages.
    pub flags: NegotiateFlags,
    /// A field containing `LmChallengeResponse` information.
    pub lm_challenge_response: LmChallengeResponse<'a>,
    // A field containing `NtChallengeResponse` information.
    pub nt_challenge_response: NtChallengeResponse<'a>,
    /// A field containing DomainName information.
    pub domain_name: Cow<'a, [u8]>,
    /// A field containing UserName information.
    pub user_name: Cow<'a, [u8]>,
    /// A field containing Workstation information.
    pub workstation_name: Cow<'a, [u8]>,
    /// A field containing EncryptedRandomSessionKey information.
    pub encrypted_random_session_key: Option<Cow<'a, [u8]>>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
    /// The message integrity for the NTLM `NegotiateMessage`, `ChallengeMessage`, and `AuthenticateMessage`.
    pub mic: Option<Cow<'a, [u8]>>,
}

impl<'a> AuthenticateMessage<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<AuthenticateMessage<'a>, Error> {
        match parse_authenticate_message(payload) {
            nom::IResult::Done(
                remaining,
                (
                    mut msg,
                    lm_challenge_response_field,
                    nt_challenge_response_field,
                    domain_name_field,
                    user_name_field,
                    workstation_name_field,
                    encrypted_random_session_key_field,
                ),
            ) => {
                let offset = payload.len() - remaining.len();

                if lm_challenge_response_field.length > 0 {
                    let data = lm_challenge_response_field.extract_data(remaining, offset)?;

                    msg.lm_challenge_response = if msg.flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM) {
                        parse_lm_response_v1(data)
                    } else {
                        parse_lm_response_v2(data)
                    }.to_full_result()
                        .map_err(NtlmError::from)?;
                }

                if nt_challenge_response_field.length > 0 {
                    let data = nt_challenge_response_field.extract_data(remaining, offset)?;

                    msg.nt_challenge_response = if msg.flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM) {
                        parse_nt_response_v1(data)
                    } else {
                        parse_nt_response_v2(data)
                    }.to_full_result()
                        .map_err(NtlmError::from)?;
                }

                msg.domain_name = Cow::from(domain_name_field.extract_data(remaining, offset)?);
                msg.user_name = Cow::from(user_name_field.extract_data(remaining, offset)?);
                msg.workstation_name = Cow::from(workstation_name_field.extract_data(remaining, offset)?);

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH)
                    && encrypted_random_session_key_field.length > 0
                {
                    msg.encrypted_random_session_key =
                        Some(Cow::from(encrypted_random_session_key_field.extract_data(remaining, offset)?))
                }

                Ok(msg)
            }
            nom::IResult::Error(err) => bail!(NtlmError::from(err)),
            nom::IResult::Incomplete(needed) => bail!(NtlmError::from(needed)),
        }
    }
}

impl<'a> WriteTo for AuthenticateMessage<'a> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        let header_size = kSignatureSize + kMesssageTypeSize + kFlagsSize + kFieldSize * 6
            + if self.version.is_some() {
                kVersionSize
            } else {
                0
            };

        buf.put_slice(kSignature);
        buf.put_u32::<LittleEndian>(MessageType::Authenticate as u32);

        let mut offset = header_size;
        let mut response_offset =
            header_size + self.domain_name.len() + self.user_name.len() + self.workstation_name.len();

        response_offset += self.lm_challenge_response
            .write_field(buf, response_offset)?;
        response_offset += self.nt_challenge_response
            .write_field(buf, response_offset)?;

        offset += self.domain_name.write_field(buf, offset)?;
        offset += self.user_name.write_field(buf, offset)?;
        offset += self.workstation_name.write_field(buf, offset)?;

        debug_assert_eq!(
            offset,
            header_size + self.domain_name.len() + self.user_name.len() + self.workstation_name.len()
        );

        response_offset += self.encrypted_random_session_key
            .write_field(buf, response_offset)?;

        let mut flags = self.flags;

        if self.encrypted_random_session_key.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        if self.version.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;
        }

        buf.put_u32::<LittleEndian>(flags.bits());

        if let Some(ref version) = self.version {
            version.write_to(buf)?;
        }

        if let Some(ref mic) = self.mic {
            buf.put_slice(mic);
        }

        self.domain_name.write_to(buf)?;
        self.user_name.write_to(buf)?;
        self.workstation_name.write_to(buf)?;

        self.lm_challenge_response.write_to(buf)?;
        self.nt_challenge_response.write_to(buf)?;

        self.encrypted_random_session_key.write_to(buf)?;

        Ok(response_offset)
    }
}

const kSignature: &[u8] = b"NTLMSSP\0";
const kSignatureSize: usize = 8;
const kMesssageTypeSize: usize = 4;
const kFlagsSize: usize = 4;
const kFieldSize: usize = 8;
const kVersionSize: usize = 8;
const kChallengeSize: usize = 8;
const kReservedSize: usize = 8;
const kAvIdSize: usize = 2;
const kAvLenSize: usize = 2;
const kNtlmClientChalengeHeaderSize: usize = 8;
const kTimestampSize: usize = 8;

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_av_pair<AvPair>,
    do_parse!(
        id: map_opt!(call!(nom::le_u16), |id| AvId::from_u16(id)) >>
        len: call!(nom::le_u16) >>
        value: map!(take!(len), Cow::from) >>
        (AvPair { id, value })
    )
);

named!(parse_av_pairs<Vec<AvPair>>, many1!(parse_av_pair));

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_negotiate_message<(NegotiateMessage, Field, Field)>,
    do_parse!(
        _signature:
            add_return_error!(
                nom::ErrorKind::Custom(MismatchedSignature as u32),
                verify!(take!(8), |signature| signature == kSignature)
            ) >>
        _msg_type: add_return_error!(
                nom::ErrorKind::Custom(MismatchedMsgType as u32),
                verify!(
                    map_opt!(nom::le_u32, |v| MessageType::from_u32(v)),
                    |msg_type| msg_type == MessageType::Negotiate
                )
            ) >>
        flags: map!(nom::le_u32, NegotiateFlags::from_bits_truncate) >>
        domain_name_field: call!(parse_field) >>
        workstation_name_field: call!(parse_field) >>
        version:
            cond!(
                flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION),
                call!(parse_version)
            ) >>
        (
            NegotiateMessage {
                flags,
                domain_name: None,
                workstation_name: None,
                version,
            },
            domain_name_field,
            workstation_name_field
        )
    )
);

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_challenge_message<(ChallengeMessage, Field, Field)>,
    do_parse!(
        _signature:
            add_return_error!(
                nom::ErrorKind::Custom(MismatchedSignature as u32),
                verify!(take!(8), |signature| signature == kSignature)
            ) >>
        _msg_type: add_return_error!(
                nom::ErrorKind::Custom(MismatchedMsgType as u32),
                verify!(
                    map_opt!(nom::le_u32, |v| MessageType::from_u32(v)),
                    |msg_type| msg_type == MessageType::Challenge
                )
            ) >>
        target_name_field: call!(parse_field) >>
        flags: map!(nom::le_u32, NegotiateFlags::from_bits_truncate) >>
        server_challenge: call!(nom::le_u64) >>
        _reserved: take!(8) >>
        target_info_field: call!(parse_field) >>
        version:
            cond!(
                flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION),
                call!(parse_version)
            ) >>
        (
            ChallengeMessage {
                flags,
                server_challenge,
                target_name: None,
                target_info: None,
                version,
            },
            target_name_field,
            target_info_field
        )
    )
);

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_authenticate_message<(AuthenticateMessage, Field, Field, Field, Field, Field, Field)>,
    do_parse!(
        _signature:
            add_return_error!(
                nom::ErrorKind::Custom(MismatchedSignature as u32),
                verify!(take!(8), |signature| signature == kSignature)
            ) >>
        _msg_type: add_return_error!(
                nom::ErrorKind::Custom(MismatchedMsgType as u32),
                verify!(
                    map_opt!(nom::le_u32, |v| MessageType::from_u32(v)),
                    |msg_type| msg_type == MessageType::Authenticate
                )
            ) >>
        lm_challenge_response_field: call!(parse_field) >>
        nt_challenge_response_field: call!(parse_field) >>
        domain_name_field: call!(parse_field) >>
        user_name_field: call!(parse_field) >>
        workstation_name_field: call!(parse_field) >>
        encrypted_random_session_key_field: call!(parse_field) >>
        flags: map!(nom::le_u32, NegotiateFlags::from_bits_truncate) >>
        version:
            cond!(
                flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION),
                call!(parse_version)
            ) >>
        (
            AuthenticateMessage {
                lm_challenge_response: LmChallengeResponse::V1 { response: Default::default() },
                nt_challenge_response: NtChallengeResponse::V1 { response: Default::default() },
                domain_name: Default::default(),
                user_name: Default::default(),
                workstation_name: Default::default(),
                encrypted_random_session_key: Default::default(),
                flags,
                version,
                mic: None,
            },
            lm_challenge_response_field,
            nt_challenge_response_field,
            domain_name_field,
            user_name_field,
            workstation_name_field,
            encrypted_random_session_key_field
        )
    )
);

named!(
    parse_lm_response_v1<LmChallengeResponse>,
    do_parse!(
        response: take!(24) >> (LmChallengeResponse::V1 {
            response: response.into(),
        })
    )
);

named!(
    parse_lm_response_v2<LmChallengeResponse>,
    do_parse!(
        response: take!(16) >> challenge: take!(8) >> (LmChallengeResponse::V2 {
            response: response.into(),
            challenge: challenge.into(),
        })
    )
);

named!(
    parse_nt_response_v1<NtChallengeResponse>,
    do_parse!(
        response: take!(24) >> (NtChallengeResponse::V1 {
            response: response.into(),
        })
    )
);

named!(
    parse_nt_response_v2<NtChallengeResponse>,
    do_parse!(
        response: take!(16) >> challenge: call!(parse_ntlm_client_challenge) >> (NtChallengeResponse::V2 {
            response: response.into(),
            challenge,
        })
    )
);

named!(
    parse_ntlm_client_challenge<NtlmClientChalenge>,
    do_parse!(
        _resp_type: verify!(call!(nom::le_u8), |v| v == 1) >> _hi_resp_type: verify!(call!(nom::le_u8), |v| v == 1)
            >> _reserved1: take!(2) >> _reserved2: take!(4) >> timestamp: call!(nom::le_u64)
            >> challenge: take!(8) >> _reserved3: take!(4) >> context: parse_av_pairs >> (NtlmClientChalenge {
            timestamp,
            challenge: challenge.into(),
            context,
        })
    )
);

struct Field {
    pub length: u16,
    pub capacity: u16,
    pub offset: u32,
}

impl Field {
    pub fn extract_data<'a>(&self, payload: &'a [u8], offset: usize) -> Result<&'a [u8], Error> {
        let start = (self.offset as usize)
            .checked_sub(offset)
            .ok_or(NtlmError::OffsetOverflow)?;
        let end = start
            .checked_add(self.length as usize)
            .ok_or(NtlmError::OffsetOverflow)?;

        if start >= payload.len() || end > payload.len() {
            bail!(NtlmError::OffsetOverflow);
        }

        Ok(&payload[start..end])
    }
}

trait WriteTo {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error>;
}

impl<'a> WriteTo for Cow<'a, [u8]> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_slice(self.as_ref());

        Ok(self.as_ref().len())
    }
}

impl<'a> WriteTo for Option<Cow<'a, [u8]>> {
    fn write_to<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        if let Some(ref data) = *self {
            buf.put_slice(data);

            Ok(data.len())
        } else {
            Ok(0)
        }
    }
}

trait WriteField {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error>;
}

impl<D: AsRef<[u8]>> WriteField for Option<D> {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error> {
        if let Some(ref data) = self.as_ref() {
            let data_size = data.as_ref().len();

            buf.put_u16::<LittleEndian>(data_size as u16);
            buf.put_u16::<LittleEndian>(data_size as u16);
            buf.put_u32::<LittleEndian>(offset as u32);

            Ok(data_size)
        } else {
            buf.put_u16::<LittleEndian>(0);
            buf.put_u16::<LittleEndian>(0);
            buf.put_u32::<LittleEndian>(offset as u32);

            Ok(0)
        }
    }
}

impl<'a> WriteField for Cow<'a, [u8]> {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error> {
        let data_size = self.as_ref().len();

        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u16::<LittleEndian>(data_size as u16);
        buf.put_u32::<LittleEndian>(offset as u32);

        Ok(data_size)
    }
}

named!(
    parse_field<Field>,
    do_parse!(
        length: call!(nom::le_u16) >> capacity: call!(nom::le_u16) >> offset: call!(nom::le_u32) >> (Field {
            length,
            capacity,
            offset,
        })
    )
);

named!(
    parse_version<Version>,
    do_parse!(
        major: call!(nom::le_u8) >> minor: call!(nom::le_u8) >> build: call!(nom::le_u16) >> _reserved: take!(3)
            >> revision: call!(nom::le_u8) >> (Version {
            major,
            minor,
            build,
            revision,
        })
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_message() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let packet: &[u8] = &[
            // Signature (8 bytes):
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
            // MessageType (4 bytes):
            0x01, 0x00, 0x00, 0x00,
            // NegotiateFlags (4 bytes):
            0x07, 0xb2, 0x00, 0x02,
            // DomainNameFields (8 bytes):
            0x06, 0x00,             // length
            0x06, 0x00,             // capacity
            0x28, 0x00, 0x00, 0x00, // offset
            // WorkstationFields (8 bytes):
            0x08, 0x00,             // length
            0x08, 0x00,             // capacity
            0x2E, 0x00, 0x00, 0x00, // offset
            // Version (8 bytes):
            0x05,                   // ProductMajorVersion (1 byte):
            0x00,                   // ProductMinorVersion (1 byte):
            0x93, 0x08,             // ProductBuild (2 bytes):
            0x00, 0x00, 0x00,       // Reserved (3 bytes):
            0x0f,                   // NTLMRevisionCurrent (1 byte):
            // Payload (variable):
            0x6d, 0x79, 0x75, 0x73, 0x65, 0x72,             // DomainName
            0x6d, 0x79, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e  // Workstation
        ];

        let message = NegotiateMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLM_NEGOTIATE_OEM
                | NegotiateFlags::NTLMSSP_REQUEST_TARGET | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
                | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
                | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
                | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                | NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION,
            domain_name: Some(Cow::from(&b"myuser"[..])),
            workstation_name: Some(Cow::from(&b"mydomain"[..])),
            version: Some(Version {
                major: 5,
                minor: 0,
                build: 2195,
                revision: 15,
            }),
        };

        assert_eq!(NegotiateMessage::parse(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.write_to(&mut buf).unwrap(), packet.len());
        assert_eq!(buf.as_slice(), packet);
    }

    #[test]
    fn challenge_message() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let packet: &[u8] = &[
            // Signature (8 bytes):
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
            // MessageType (4 bytes):
            0x02, 0x00, 0x00, 0x00,
            // TargetNameFields (8 bytes):
            0x0c, 0x00,
            0x0c, 0x00,
            0x30, 0x00, 0x00, 0x00,
            // NegotiateFlags (4 bytes):
            0x01, 0x02, 0x81, 0x00,
            // ServerChallenge (8 bytes):
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            // Reserved (8 bytes):
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // TargetInfoFields (8 bytes):
            0x62, 0x00,
            0x62, 0x00,
            0x3c, 0x00, 0x00, 0x00,
            // TargetName (variable):
            0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00,
            // TargetInfoFields (8 bytes):
            //   Domain name subblock:
            //     Type: 2 (Domain name, 0x0200)
            0x02, 0x00,
            //     Length: 12 bytes (0x0c00)
            0x0c, 0x00,
            //     Data: "DOMAIN"
            0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00,
            //   Server name subblock:
            //     Type: 1 (Server name, 0x0100)
            0x01, 0x00,
            //     Length: 12 bytes (0x0c00)
            0x0c, 0x00,
            //     Data: "SERVER"
            0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00, 0x45, 0x00, 0x52, 0x00,
            //   DNS domain name subblock:
            //     Type: 4 (DNS domain name, 0x0400)
            0x04, 0x00,
            //     Length: 20 bytes (0x1400)
            0x14, 0x00,
            //     Data: "domain.com"
            0x64, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00,
            // DNS server name subblock:
            //   Type: 3 (DNS server name, 0x0300)
            0x03, 0x00,
            0x22, 0x00,
            0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x6d, 0x00,
            0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00,
            // Terminator subblock:
            //   Type: 0 (terminator, 0x0000)
            0x00, 0x00,
            //   Length: 0 bytes (0x0000)
            0x00, 0x00
        ];

        let message = ChallengeMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
                | NegotiateFlags::NTLMSSP_TARGET_TYPE_DOMAIN
                | NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO,
            server_challenge: 0x0807060504030201,
            target_name: Some(utf16!("DOMAIN")),
            target_info: Some(vec![
                nb_domain_name("DOMAIN"),
                nb_computer_name("SERVER"),
                dns_domain_name("domain.com"),
                dns_computer_name("server.domain.com"),
                eol(),
            ]),
            version: None,
        };

        assert_eq!(ChallengeMessage::parse(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.write_to(&mut buf).unwrap(), packet.len());
        assert_eq!(buf.as_slice(), packet);
    }

    #[test]
    fn authenticate_message() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let packet: &[u8] = &[
            // Signature (8 bytes):
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
            // MessageType (4 bytes):
            0x03, 0x00, 0x00, 0x00,
            // LmChallengeResponseFields (8 bytes):
            0x18, 0x00,
            0x18, 0x00,
            0x6a, 0x00, 0x00, 0x00,
            // NtChallengeResponseFields (8 bytes):
            0x18, 0x00,
            0x18, 0x00,
            0x82, 0x00, 0x00, 0x00,
            // DomainNameFields (8 bytes):
            0x0c, 0x00,
            0x0c, 0x00,
            0x40, 0x00, 0x00, 0x00,
            // UserNameFields (8 bytes):
            0x08, 0x00,
            0x08, 0x00,
            0x4c, 0x00, 0x00, 0x00,
            // WorkstationFields (8 bytes):
            0x16, 0x00,
            0x16, 0x00,
            0x54, 0x00, 0x00, 0x00,
            // EncryptedRandomSessionKeyFields (8 bytes):
            0x00, 0x00,
            0x00, 0x00,
            0x9a, 0x00, 0x00, 0x00,
            // NegotiateFlags (4 bytes):
            0x01, 0x02, 0x00, 0x00,
            // DomainName (variable):
            0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, 0x49, 0x00, 0x4e, 0x00,
            // UserName (variable):
            0x75, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00,
            // Workstation (variable):
            0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, 0x53, 0x00, 0x54, 0x00,
            0x41, 0x00, 0x54, 0x00, 0x49, 0x00, 0x4f, 0x00, 0x4e, 0x00,
            // LmChallengeResponse (variable):
            0xc3, 0x37, 0xcd, 0x5c, 0xbd, 0x44, 0xfc, 0x97, 0x82, 0xa6, 0x67, 0xaf,
            0x6d, 0x42, 0x7c, 0x6d, 0xe6, 0x7c, 0x20, 0xc2, 0xd3, 0xe7, 0x7c, 0x56,
            // NtChallengeResponse (variable):
            0x25, 0xa9, 0x8c, 0x1c, 0x31, 0xe8, 0x18, 0x47, 0x46, 0x6b, 0x29, 0xb2,
            0xdf, 0x46, 0x80, 0xf3, 0x99, 0x58, 0xfb, 0x8c, 0x21, 0x3a, 0x9c, 0xc6,
        ];

        let message = AuthenticateMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM,
            lm_challenge_response: LmChallengeResponse::V1 {
                response: Cow::from(vec![
                    0xc3, 0x37, 0xcd, 0x5c, 0xbd, 0x44, 0xfc, 0x97, 0x82, 0xa6, 0x67, 0xaf, 0x6d, 0x42, 0x7c, 0x6d,
                    0xe6, 0x7c, 0x20, 0xc2, 0xd3, 0xe7, 0x7c, 0x56,
                ]),
            },
            nt_challenge_response: NtChallengeResponse::V1 {
                response: Cow::from(vec![
                    0x25, 0xa9, 0x8c, 0x1c, 0x31, 0xe8, 0x18, 0x47, 0x46, 0x6b, 0x29, 0xb2, 0xdf, 0x46, 0x80, 0xf3,
                    0x99, 0x58, 0xfb, 0x8c, 0x21, 0x3a, 0x9c, 0xc6,
                ]),
            },
            domain_name: utf16!("DOMAIN"),
            user_name: utf16!("user"),
            workstation_name: utf16!("WORKSTATION"),
            encrypted_random_session_key: None,
            version: None,
            mic: None,
        };

        assert_eq!(AuthenticateMessage::parse(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.write_to(&mut buf).unwrap(), packet.len());
        assert_eq!(buf.as_slice(), packet);
    }
}
