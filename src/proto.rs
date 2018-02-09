#![allow(non_upper_case_globals)]

use std::borrow::Cow;
use std::fmt;
use std::io::Cursor;
use std::iter::{self, FromIterator};
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{Buf, BufMut};
use encoding::{DecoderTrap, EncoderTrap, Encoding};
use encoding::codec::utf_16::UTF_16LE_ENCODING;

use failure::Error;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U24, U7, U8};
use itertools;
use nom;
use num::FromPrimitive;
use rand::{thread_rng, Rng};
use time::{at_utc, get_time, Timespec};

use crypto::buffer::{BufferResult, RefReadBuffer, RefWriteBuffer};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::md5::Md5;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::Encryptor;
use des::{BlockCipher, Des};
use md4::{Digest as MD4Digest, Md4};

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

bitflags! {
    /// A 32-bit value indicating server or client configuration.
    pub struct MsvAvFlags: u32 {
        /// Indicates to the client that the account authentication is constrained.
        const AccountAuthenticationContrained = 0x0000_0001;
        /// Indicates that the client is providing message integrity in the MIC field
        /// (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
        const ProvidingMessageIntegrityMIC = 0x0000_0002;
        /// Indicates that the client is providing a target SPN generated from an untrusted source.
        const TargetSPNFromUntrustedSource = 0x0000_0004;
    }
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

    pub fn to_str(&self) -> Option<String> {
        match self.id {
            AvId::NbComputerName
            | AvId::NbDomainName
            | AvId::DnsComputerName
            | AvId::DnsDomainName
            | AvId::DnsTreeName
            | AvId::TargetName => UTF_16LE_ENCODING
                .decode(self.value.as_ref(), DecoderTrap::Ignore)
                .ok(),
            _ => None,
        }
    }

    pub fn to_flags(&self) -> Option<MsvAvFlags> {
        if self.id == AvId::Flags && self.value.len() >= mem::size_of::<u32>() {
            MsvAvFlags::from_bits(LittleEndian::read_u32(self.value.as_ref()))
        } else {
            None
        }
    }

    pub fn to_single_host(&self) -> Option<SingleHostData> {
        if self.id == AvId::SingleHost {
            parse_single_host_data(self.value.as_ref()).to_result().ok()
        } else {
            None
        }
    }

    pub fn to_timestamp(&self) -> Option<FileTime> {
        if self.id == AvId::Timestamp && self.value.len() >= mem::size_of::<FileTime>() {
            FileTime::from_wire(self.value.as_ref()).ok()
        } else {
            None
        }
    }
}

impl<'a> ToWire for AvPair<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u16::<LittleEndian>(self.id as u16);
        buf.put_u16::<LittleEndian>(self.value.as_ref().len() as u16);
        buf.put_slice(self.value.as_ref());

        Ok(self.size())
    }
}

impl<'a> fmt::Display for AvPair<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.id {
            AvId::EOL => write!(f, "EOL"),
            AvId::NbComputerName => write!(f, "NbComputerName: {}", self.to_str().unwrap_or_default()),
            AvId::NbDomainName => write!(f, "NbDomainName: {}", self.to_str().unwrap_or_default()),
            AvId::DnsComputerName => write!(f, "DnsComputerName: {}", self.to_str().unwrap_or_default()),
            AvId::DnsDomainName => write!(f, "DnsDomainName: {}", self.to_str().unwrap_or_default()),
            AvId::DnsTreeName => write!(f, "DnsTreeName: {}", self.to_str().unwrap_or_default()),
            AvId::Flags => write!(f, "Flags: {:?}", self.to_flags()),
            AvId::Timestamp => write!(
                f,
                "Timestamp: {}",
                self.to_timestamp()
                    .map(|ts| at_utc(Timespec::from(ts)).ctime().to_string())
                    .unwrap_or_default()
            ),
            AvId::SingleHost => write!(f, "SingleHost: {:?}", self.to_single_host()),
            AvId::TargetName => write!(f, "TargetName: {}", self.to_str().unwrap_or_default()),
            AvId::ChannelBindings => write!(f, "ChannelBindings: {:?}", self.value),
        }
    }
}

pub fn oem<S: AsRef<str>>(s: S) -> Vec<u8> {
    s.as_ref().as_bytes().to_vec()
}

pub fn utf16<S: AsRef<str>>(s: S) -> Vec<u8> {
    UTF_16LE_ENCODING
        .encode(s.as_ref(), EncoderTrap::Ignore)
        .unwrap()
}

pub fn from_utf16<B: AsRef<[u8]>>(buf: B) -> Result<String, Error> {
    UTF_16LE_ENCODING
        .decode(buf.as_ref(), DecoderTrap::Ignore)
        .map_err(|_| NtlmError::Utf16Error.into())
}

pub fn eol<'a>() -> AvPair<'a> {
    AvPair {
        id: AvId::EOL,
        value: Default::default(),
    }
}

pub fn timestamp<'a>(ts: Timespec) -> AvPair<'a> {
    let mut buf = vec![];

    FileTime::from(ts).to_wire(&mut buf).unwrap();

    AvPair {
        id: AvId::Timestamp,
        value: buf.into(),
    }
}

pub fn nb_computer_name<'a>(computer_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::NbComputerName,
        value: utf16(computer_name).into(),
    }
}

pub fn nb_domain_name<'a>(domain_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::NbDomainName,
        value: utf16(domain_name).into(),
    }
}

pub fn dns_computer_name<'a>(computer_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::DnsComputerName,
        value: utf16(computer_name).into(),
    }
}

pub fn dns_domain_name<'a>(domain_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::DnsDomainName,
        value: utf16(domain_name).into(),
    }
}

pub fn dns_tree_name<'a>(tree_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::DnsTreeName,
        value: utf16(tree_name).into(),
    }
}

pub fn target_name<'a>(target_name: &str) -> AvPair<'a> {
    AvPair {
        id: AvId::TargetName,
        value: utf16(target_name).into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FileTime {
    pub lo: u32,
    pub hi: u32,
}

const NANOS_PER_SEC: u64 = 1_000_000_000;
const INTERVALS_PER_SEC: u64 = NANOS_PER_SEC / 100;
const INTERVALS_TO_UNIX_EPOCH: u64 = 11_644_473_600 * INTERVALS_PER_SEC;

impl FileTime {
    pub fn now() -> Self {
        get_time().into()
    }
}

impl From<FileTime> for u64 {
    fn from(filetime: FileTime) -> Self {
        (u64::from(filetime.hi) << 32) + u64::from(filetime.lo)
    }
}

impl From<FileTime> for Timespec {
    fn from(filetime: FileTime) -> Self {
        let ts = u64::from(filetime);

        let nsecs = ((ts % INTERVALS_PER_SEC) * 100) as i32;
        let secs = ((ts / INTERVALS_PER_SEC) as i64) - ((INTERVALS_TO_UNIX_EPOCH / INTERVALS_PER_SEC) as i64);

        Timespec::new(secs, nsecs)
    }
}

impl From<u64> for FileTime {
    fn from(n: u64) -> Self {
        FileTime {
            lo: (n & ((1 << 32) - 1)) as u32,
            hi: (n >> 32) as u32,
        }
    }
}

impl From<Timespec> for FileTime {
    fn from(ts: Timespec) -> Self {
        let sec = ts.sec + (INTERVALS_TO_UNIX_EPOCH / INTERVALS_PER_SEC) as i64;
        let nsec = ts.nsec as u64 / INTERVALS_PER_SEC;
        let intervals = (sec as u64 * INTERVALS_PER_SEC + nsec) as u64;

        FileTime::from(intervals)
    }
}

impl<'a> FromWire<'a> for FileTime {
    type Type = FileTime;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error> {
        if payload.len() < kFileTimeSize {
            bail!(NtlmError::BufferOverflow)
        }

        let mut cur = Cursor::new(payload);

        Ok(FileTime {
            lo: cur.get_u32::<LittleEndian>(),
            hi: cur.get_u32::<LittleEndian>(),
        })
    }
}

impl ToWire for FileTime {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u32::<LittleEndian>(self.lo);
        buf.put_u32::<LittleEndian>(self.hi);

        Ok(kFileTimeSize)
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
        const NTLMSSP_NEGOTIATE_OEM = 0x0000_0002;
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

        const NTLMSSP_NEGOTIATE_NETWARE = 0x0000_0100;
        /// If set, requests usage of the NTLM v1 session security protocol.
        const NTLMSSP_NEGOTIATE_NTLM = 0x0000_0200;
        /// If set, the connection SHOULD be anonymous.
        const NTLMSSP_NEGOTIATE_ANONYMOUS = 0x0000_0800;
        /// If set, the domain name is provided (section 2.2.1.1).
        const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x0000_1000;
        /// This flag indicates whether the Workstation field is present.
        const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x0000_2000;
        /// Sent by the server to indicate that the server and client are on the same machine.
        /// This implies that the server will include a local security context handle in the Type 2 message,
        /// for use in local authentication.
        const NTLMSSP_NEGOTIATE_LOCAL_CALL = 0x0000_4000;
        /// If set, requests the presence of a signature block on all messages.
        const NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;
        /// If set, TargetName MUST be a domain name.
        const NTLMSSP_TARGET_TYPE_DOMAIN = 0x0001_0000;
        /// If set, TargetName MUST be a server name.
        const NTLMSSP_TARGET_TYPE_SERVER = 0x0002_0000;
        /// Sent by the server in the Type 2 message to indicate
        /// that the target authentication realm is a share (presumably for share-level authentication).
        const NTLMSSP_TARGET_TYPE_SHARE = 0x0004_0000;
        /// If set, requests usage of the NTLM v2 session security.
        const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x0008_0000;
        /// If set, requests an identify level token.
        const NTLMSSP_NEGOTIATE_IDENTIFY = 0x0010_0000;

        const NTLMSSP_REQUEST_ACCEPT_RESPONSE = 0x0020_0000;
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

impl Default for NegotiateFlags {
    fn default() -> NegotiateFlags {
        NegotiateFlags::empty()
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum NtlmSecurityLevel {
    /// Server sends LM and NTLM response and never uses extended session security.
    /// Clients use LM and NTLM authentication, and never use extended session security.
    /// DCs accept LM, NTLM, and NTLM v2 authentication.
    Level0,
    /// Servers use NTLM v2 session security if it is negotiated.
    /// Clients use LM and NTLM authentication and use extended session security
    /// if the server supports it. DCs accept LM, NTLM, and NTLM v2 authentication.
    Level1,
    /// Server sends NTLM response only.
    /// Clients use only NTLM authentication and use extended session security if the server supports it.
    /// DCs accept LM, NTLM, and NTLM v2 authentication.
    Level2,
    /// Server sends NTLM v2 response only.
    /// Clients use NTLM v2 authentication and use extended session security if the server supports it.
    /// DCs accept LM, NTLM, and NTLM v2 authentication.
    Level3,
    /// DCs refuse LM responses.
    /// Clients use NTLM authentication and use extended session security if the server supports it.
    /// DCs refuse LM authentication but accept NTLM and NTLM v2 authentication.
    Level4,
    /// DCs refuse LM and NTLM responses, and accept only NTLM v2.
    /// Clients use NTLM v2 authentication and use extended session security if the server supports it.
    /// DCs refuse NTLM and LM authentication, and accept only NTLM v2 authentication.
    Level5,
}

impl Default for NtlmSecurityLevel {
    fn default() -> Self {
        NtlmSecurityLevel::Level3
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

#[derive(Clone, Debug, PartialEq)]
pub enum NtlmMessage<'a> {
    Negotiate(NegotiateMessage<'a>),
    Challenge(ChallengeMessage<'a>),
    Authenticate(AuthenticateMessage<'a>),
}

impl<'a> FromWire<'a> for NtlmMessage<'a> {
    type Type = NtlmMessage<'a>;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error> {
        if payload.len() < kSignatureSize + kMesssageTypeSize {
            bail!(NtlmError::IncompleteMessage(nom::Needed::Unknown))
        }

        let signature = &payload[..kSignatureSize];

        if signature != kSignature {
            bail!(NtlmError::MismatchedSignature)
        }

        match MessageType::from_u32(LittleEndian::read_u32(&payload[kSignatureSize..])) {
            Some(MessageType::Negotiate) => NegotiateMessage::from_wire(payload).map(|msg| NtlmMessage::Negotiate(msg)),
            Some(MessageType::Challenge) => ChallengeMessage::from_wire(payload).map(|msg| NtlmMessage::Challenge(msg)),
            Some(MessageType::Authenticate) => {
                AuthenticateMessage::from_wire(payload).map(|msg| NtlmMessage::Authenticate(msg))
            }
            _ => bail!(NtlmError::MismatchedMsgType),
        }
    }
}

impl<'a> ToWire for NtlmMessage<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        match *self {
            NtlmMessage::Negotiate(ref message) => message.to_wire(buf),
            NtlmMessage::Challenge(ref message) => message.to_wire(buf),
            NtlmMessage::Authenticate(ref message) => message.to_wire(buf),
        }
    }
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

impl ToWire for Version {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u8(self.major);
        buf.put_u8(self.minor);
        buf.put_u16::<LittleEndian>(self.build);
        buf.put_uint::<LittleEndian>(0, 3);
        buf.put_u8(self.revision);

        Ok(kVersionSize)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// Version 15 of the NTLMSSP is in use.
pub const NTLMSSP_REVISION_W2K3: u8 = 0x0f;

/// The `NegotiateMessage` defines an NTLM Negotiate message that is sent from the client to the server.
///
/// This message allows the client to specify its supported NTLM options to the server.
#[derive(Debug, Clone, PartialEq)]
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
    pub fn into_owned<'b>(self) -> NegotiateMessage<'b> {
        NegotiateMessage {
            flags: self.flags,
            domain_name: self.domain_name.map(|s| Cow::from(s.into_owned())),
            workstation_name: self.workstation_name.map(|s| Cow::from(s.into_owned())),
            version: self.version,
        }
    }
}

impl<'a> FromWire<'a> for NegotiateMessage<'a> {
    type Type = NegotiateMessage<'a>;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error> {
        match parse_negotiate_message(payload) {
            nom::IResult::Done(remaining, (mut msg, domain_name_field, workstation_name_field)) => {
                let offset = payload.len() - remaining.len();

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION)
                    && domain_name_field.offset as usize >= offset + kVersionSize
                {
                    msg.version = parse_version(remaining).to_full_result().ok();
                }

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

impl<'a> ToWire for NegotiateMessage<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
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
            version.to_wire(buf)?;
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
    pub server_challenge: Cow<'a, [u8]>,
    /// A field containing TargetName information.
    pub target_name: Option<Cow<'a, [u8]>>,
    /// A field containing TargetInfo information.
    pub target_info: Option<Vec<AvPair<'a>>>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
}

impl<'a> ChallengeMessage<'a> {
    pub fn contains(&self, id: AvId) -> bool {
        self.get(id).is_some()
    }

    pub fn get(&self, id: AvId) -> Option<&AvPair> {
        self.target_info
            .as_ref()
            .and_then(|target_info| target_info.iter().find(|av_pair| av_pair.id == id))
    }
}

impl<'a> FromWire<'a> for ChallengeMessage<'a> {
    type Type = ChallengeMessage<'a>;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error> {
        match parse_challenge_message(payload) {
            nom::IResult::Done(remaining, (mut msg, target_name_field, target_info_field)) => {
                let offset = payload.len() - remaining.len();

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION)
                    && target_name_field.offset as usize >= offset + kVersionSize
                {
                    msg.version = parse_version(remaining).to_full_result().ok();
                }

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

impl<'a> ToWire for ChallengeMessage<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
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

        buf.put_slice(self.server_challenge.as_ref());
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
            version.to_wire(buf)?;
        }

        if let Some(ref target_name) = self.target_name {
            buf.put_slice(target_name.as_ref());
        }

        if let Some(ref target_info) = self.target_info {
            for av_pair in target_info {
                av_pair.to_wire(buf)?;
            }
        }

        Ok(offset)
    }
}

pub type NtResponseKey = GenericArray<u8, U16>;
pub type LmResponseKey = GenericArray<u8, U16>;

pub fn lm_owf_v1<S: AsRef<str>>(password: S) -> LmResponseKey {
    let key = password
        .as_ref()
        .to_uppercase()
        .into_bytes()
        .into_iter()
        .chain(iter::repeat(0))
        .take(14)
        .collect::<Vec<u8>>();

    let mut buf = vec![];

    buf.extend_from_slice(b"KGS!@#$%");
    buf.extend_from_slice(b"KGS!@#$%");

    for (key, buf) in key.chunks(7).zip(buf.chunks_mut(8)) {
        Des::new(&make_key(GenericArray::from_slice(key))).encrypt_block(GenericArray::from_mut_slice(buf));
    }

    LmResponseKey::from_iter(buf.into_iter())
}

fn make_key(key7: &GenericArray<u8, U7>) -> GenericArray<u8, U8> {
    GenericArray::from([
        (key7[0] >> 1) << 1,
        (((key7[0] & 0x01) << 6) | (key7[1] >> 2)) << 1,
        (((key7[1] & 0x03) << 5) | (key7[2] >> 3)) << 1,
        (((key7[2] & 0x07) << 4) | (key7[3] >> 4)) << 1,
        (((key7[3] & 0x0F) << 3) | (key7[4] >> 5)) << 1,
        (((key7[4] & 0x1F) << 2) | (key7[5] >> 6)) << 1,
        (((key7[5] & 0x3F) << 1) | (key7[6] >> 7)) << 1,
        (key7[6] & 0x7F) << 1,
    ])
}

pub fn nt_owf_v1<S: AsRef<str>>(password: S) -> NtResponseKey {
    NtResponseKey::from_iter(Md4::digest(&utf16(password)))
}

pub fn lm_owf_v2<S: AsRef<str>>(username: S, password: S, domain: S) -> LmResponseKey {
    nt_owf_v2(username, password, domain)
}

pub fn nt_owf_v2<S: AsRef<str>>(username: S, password: S, domain: S) -> NtResponseKey {
    let key = nt_owf_v1(password);

    hmac_md5(
        &key,
        &[
            &utf16(username.as_ref().to_uppercase()),
            &utf16(domain.as_ref()),
        ],
    )
}

/// Indicates the encryption of an 8-byte data item D with the 16-byte key K
/// using the Data Encryption Standard Long (DESL) algorithm.
fn desl(key: &GenericArray<u8, U16>, data: &GenericArray<u8, U8>) -> GenericArray<u8, U24> {
    let key = key.iter()
        .cloned()
        .chain(iter::repeat(0))
        .take(21)
        .collect::<Vec<u8>>();

    let mut buf = itertools::repeat_n(&data, 3)
        .flat_map(|data| data.iter())
        .cloned()
        .collect::<Vec<u8>>();

    for (key, buf) in key.chunks(7).zip(buf.chunks_mut(8)) {
        Des::new(&make_key(GenericArray::from_slice(key))).encrypt_block(GenericArray::from_mut_slice(buf));
    }

    GenericArray::from_iter(buf.into_iter())
}

pub fn rc4(key: &GenericArray<u8, U16>, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; data.len()];

    match Rc4::new(key)
        .encrypt(
            &mut RefReadBuffer::new(data),
            &mut RefWriteBuffer::new(&mut buf),
            true,
        )
        .map_err(NtlmError::from)?
    {
        BufferResult::BufferUnderflow => Ok(buf),
        BufferResult::BufferOverflow => bail!(NtlmError::BufferOverflow),
    }
}

pub fn hmac_md5(key: &GenericArray<u8, U16>, data: &[&[u8]]) -> GenericArray<u8, U16> {
    let mut hmac = Hmac::new(Md5::new(), key);

    for b in data {
        hmac.input(b);
    }

    GenericArray::from_iter(hmac.result().code().iter().cloned())
}

pub type ServerChallenge = GenericArray<u8, U8>;
pub type ClientChallenge = GenericArray<u8, U8>;

pub fn generate_challenge() -> GenericArray<u8, U8> {
    GenericArray::from_iter(thread_rng().gen_iter().take(8))
}

pub type SessionKey = GenericArray<u8, U16>;

pub fn generate_random_session_key() -> SessionKey {
    SessionKey::from_iter(thread_rng().gen_iter().take(16))
}

pub fn generate_session_base_key_v1(nt_response_key: &NtResponseKey) -> SessionKey {
    SessionKey::from_iter(Md4::digest(nt_response_key))
}

pub fn generate_session_base_key_v2(
    nt_response_key: &NtResponseKey,
    nt_proof_str: &GenericArray<u8, U16>,
) -> SessionKey {
    hmac_md5(nt_response_key, &[nt_proof_str])
}

pub type KeyExchangeKey = GenericArray<u8, U16>;

pub fn generate_key_exchange_key(
    flags: NegotiateFlags,
    lm_response_key: &LmResponseKey,
    session_base_key: &SessionKey,
    server_challenge: &ServerChallenge,
    lm_challenge_response: &GenericArray<u8, U8>,
) -> KeyExchangeKey {
    if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        hmac_md5(session_base_key, &[server_challenge, lm_challenge_response])
    } else if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_LM_KEY) {
        let key = lm_response_key
            .iter()
            .cloned()
            .take(8)
            .chain(iter::repeat(0xBD))
            .take(14)
            .collect::<Vec<u8>>();

        let mut buf = itertools::repeat_n(lm_challenge_response, 2)
            .flat_map(|data| data.iter())
            .cloned()
            .collect::<Vec<u8>>();

        for (key, buf) in key.chunks(7).zip(buf.chunks_mut(8)) {
            Des::new(&make_key(GenericArray::from_slice(key))).encrypt_block(GenericArray::from_mut_slice(buf));
        }

        KeyExchangeKey::from_iter(buf.into_iter())
    } else if flags.contains(NegotiateFlags::NTLMSSP_REQUEST_NON_NT_SESSION_KEY) {
        KeyExchangeKey::from_iter(
            lm_response_key
                .iter()
                .cloned()
                .take(8)
                .chain(iter::repeat(0))
                .take(16),
        )
    } else {
        *session_base_key
    }
}

/// The key used for signing messages.
pub type SignKey = GenericArray<u8, U16>;

const kClientSigningKeyMagic: &[u8] = b"session key to client-to-server signing key magic constant\0";
const kServerSigningKeyMagic: &[u8] = b"session key to server-to-client signing key magic constant\0";

pub fn generate_sign_key(flags: NegotiateFlags, exported_session_key: &SessionKey, is_server: bool) -> Option<SignKey> {
    if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        let mut md5 = Md5::new();

        md5.input(exported_session_key);
        md5.input(if is_server {
            kServerSigningKeyMagic
        } else {
            kClientSigningKeyMagic
        });

        let mut hash = vec![0u8; 16];
        md5.result(&mut hash);

        Some(SignKey::from_iter(hash.into_iter()))
    } else {
        None
    }
}

/// The key used for sealing messages.
pub type SealKey = GenericArray<u8, U16>;

const kClientSealingKeyMagic: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const kServerSealingKeyMagic: &[u8] = b"session key to server-to-client sealing key magic constant\0";

pub fn generate_seal_key(
    flags: NegotiateFlags,
    exported_session_key: &SessionKey,
    is_server: bool,
    current_revision: u8,
) -> SealKey {
    if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        let mut md5 = Md5::new();

        md5.input(if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_128) {
            exported_session_key
        } else if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_56) {
            &exported_session_key[..7]
        } else {
            &exported_session_key[..5]
        });

        md5.input(if is_server {
            kServerSealingKeyMagic
        } else {
            kClientSealingKeyMagic
        });

        let mut hash = vec![0u8; 16];
        md5.result(&mut hash);

        SealKey::from_iter(hash.into_iter())
    } else if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_LM_KEY)
        || (flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_DATAGRAM) && current_revision >= NTLMSSP_REVISION_W2K3)
    {
        SealKey::from_iter(if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_56) {
            exported_session_key
                .iter()
                .cloned()
                .take(7)
                .chain(vec![0xA0].into_iter())
        } else {
            exported_session_key
                .iter()
                .cloned()
                .take(5)
                .chain(vec![0xE5, 0x38, 0xB0].into_iter())
        })
    } else {
        *exported_session_key
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

impl<'a> LmChallengeResponse<'a> {
    pub fn v1(lm_response_key: &LmResponseKey, server_challenge: &ServerChallenge) -> LmChallengeResponse<'a> {
        let lm_response_data = desl(lm_response_key, server_challenge);

        LmChallengeResponse::V1 {
            response: lm_response_data.to_vec().into(),
        }
    }

    pub fn with_extended_session_security(client_challenge: &ClientChallenge) -> LmChallengeResponse<'a> {
        let mut lm_response_data = vec![];

        lm_response_data.extend_from_slice(client_challenge);
        lm_response_data.extend(iter::repeat(0).take(16));

        LmChallengeResponse::V1 {
            response: lm_response_data.into(),
        }
    }

    pub fn v2(
        lm_response_key: &LmResponseKey,
        server_challenge: &ServerChallenge,
        client_challenge: &ClientChallenge,
    ) -> LmChallengeResponse<'a> {
        let lm_response_data = hmac_md5(lm_response_key, &[server_challenge, client_challenge]);

        LmChallengeResponse::V2 {
            response: lm_response_data.to_vec().into(),
            challenge: client_challenge.to_vec().into(),
        }
    }

    pub fn response(&self) -> Cow<'a, [u8]> {
        match *self {
            LmChallengeResponse::V1 { ref response } | LmChallengeResponse::V2 { ref response, .. } => response.clone(),
        }
    }
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

impl<'a> ToWire for LmChallengeResponse<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
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

impl<'a> NtChallengeResponse<'a> {
    pub fn v1(nt_response_key: &NtResponseKey, server_challenge: &ServerChallenge) -> NtChallengeResponse<'a> {
        let nt_response_data = desl(nt_response_key, server_challenge);

        NtChallengeResponse::V1 {
            response: nt_response_data.to_vec().into(),
        }
    }

    pub fn with_extended_session_security(
        nt_response_key: &NtResponseKey,
        server_challenge: &ServerChallenge,
        client_challenge: &ClientChallenge,
    ) -> NtChallengeResponse<'a> {
        let mut md5 = Md5::new();
        md5.input(server_challenge);
        md5.input(client_challenge);

        let mut hash = vec![0u8; 16];
        md5.result(&mut hash);

        let nt_response_data = desl(nt_response_key, GenericArray::from_slice(&hash[..8]));

        NtChallengeResponse::V1 {
            response: nt_response_data.to_vec().into(),
        }
    }

    pub fn v2(
        nt_response_key: &NtResponseKey,
        server_challenge: &ServerChallenge,
        client_challenge: &ClientChallenge,
        current_time: FileTime,
        target_info: Vec<AvPair<'a>>,
    ) -> NtChallengeResponse<'a> {
        let mut client_data = vec![];

        let client_challenge = NtlmClientChalenge {
            timestamp: current_time.into(),
            challenge_from_client: client_challenge.to_vec().into(),
            target_info,
        };

        client_challenge.to_wire(&mut client_data).unwrap();

        let nt_proof_str = hmac_md5(nt_response_key, &[server_challenge, &client_data]);

        NtChallengeResponse::V2 {
            response: nt_proof_str.to_vec().into(),
            challenge: client_challenge,
        }
    }

    pub fn response(&self) -> Cow<'a, [u8]> {
        match *self {
            NtChallengeResponse::V1 { ref response } | NtChallengeResponse::V2 { ref response, .. } => response.clone(),
        }
    }
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

impl<'a> ToWire for NtChallengeResponse<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
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

                let challenge_size = challenge.to_wire(buf)?;

                Ok(response.len() + challenge_size)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NtlmClientChalenge<'a> {
    pub timestamp: FileTime,
    pub challenge_from_client: Cow<'a, [u8]>,
    pub target_info: Vec<AvPair<'a>>,
}

impl<'a> NtlmClientChalenge<'a> {
    pub fn size(&self) -> usize {
        kNtlmClientChalengeHeaderSize + kTimestampSize + self.challenge_from_client.len() + 8
            + self.target_info
                .iter()
                .map(|av_pair| av_pair.size())
                .sum::<usize>() + match self.target_info.last() {
            Some(av_pair) if av_pair.id == AvId::EOL => 0,
            _ => eol().size(),
        }
    }
}

impl<'a> ToWire for NtlmClientChalenge<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_u8(0x01); // RespType
        buf.put_u8(0x01); // HiRespType
        buf.put_u16::<LittleEndian>(0); // Reserved1
        buf.put_u32::<LittleEndian>(0); // Reserved2
        buf.put_u64::<LittleEndian>(u64::from(self.timestamp));
        buf.put_slice(self.challenge_from_client.as_ref());
        buf.put_u32::<LittleEndian>(0); // Reserved3

        for av_pair in &self.target_info {
            av_pair.to_wire(buf)?;
        }

        match self.target_info.last() {
            Some(av_pair) if av_pair.id == AvId::EOL => {}
            _ => {
                eol().to_wire(buf)?;
            }
        }

        buf.put_u32::<LittleEndian>(0); // Reserved4

        Ok(self.size())
    }
}

pub fn compute_response<'a>(
    flags: NegotiateFlags,
    nt_response_key: &NtResponseKey,
    lm_response_key: &LmResponseKey,
    server_challenge: &ServerChallenge,
    client_challenge: &ClientChallenge,
    current_time: FileTime,
    target_info: Vec<AvPair<'a>>,
) -> (NtChallengeResponse<'a>, LmChallengeResponse<'a>, SessionKey) {
    if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        (
            NtChallengeResponse::with_extended_session_security(nt_response_key, server_challenge, client_challenge),
            LmChallengeResponse::with_extended_session_security(client_challenge),
            generate_session_base_key_v1(nt_response_key),
        )
    } else if flags.contains(NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM) {
        (
            NtChallengeResponse::v1(nt_response_key, server_challenge),
            LmChallengeResponse::v1(lm_response_key, server_challenge),
            generate_session_base_key_v1(nt_response_key),
        )
    } else {
        let nt_response = NtChallengeResponse::v2(
            nt_response_key,
            server_challenge,
            client_challenge,
            current_time,
            target_info,
        );
        let lm_response = LmChallengeResponse::v2(lm_response_key, server_challenge, client_challenge);
        let nt_proof_str = nt_response.response();
        let nt_proof_str = GenericArray::from_slice(nt_proof_str.as_ref());

        (
            nt_response,
            lm_response,
            generate_session_base_key_v2(nt_response_key, nt_proof_str),
        )
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
    pub lm_challenge_response: Option<LmChallengeResponse<'a>>,
    // A field containing `NtChallengeResponse` information.
    pub nt_challenge_response: Option<NtChallengeResponse<'a>>,
    /// A field containing DomainName information.
    pub domain_name: Cow<'a, [u8]>,
    /// A field containing UserName information.
    pub user_name: Cow<'a, [u8]>,
    /// A field containing Workstation information.
    pub workstation_name: Cow<'a, [u8]>,
    /// A field containing EncryptedRandomSessionKey information.
    pub session_key: Option<Cow<'a, [u8]>>,
    /// This structure should be used for debugging purposes only.
    pub version: Option<Version>,
    /// The message integrity for the NTLM `NegotiateMessage`, `ChallengeMessage`, and `AuthenticateMessage`.
    pub mic: Option<Cow<'a, [u8]>>,
}

impl<'a> FromWire<'a> for AuthenticateMessage<'a> {
    type Type = AuthenticateMessage<'a>;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error> {
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
                    session_key_field,
                ),
            ) => {
                let offset = payload.len() - remaining.len();

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION)
                    && lm_challenge_response_field.offset as usize >= offset + kVersionSize
                {
                    msg.version = parse_version(remaining).to_full_result().ok();
                }

                msg.lm_challenge_response = if lm_challenge_response_field.length > 0 {
                    debug!(
                        "extract LM challenge response at {} with {} bytes, current offset {}",
                        lm_challenge_response_field.offset, lm_challenge_response_field.length, offset
                    );

                    let data = lm_challenge_response_field.extract_data(remaining, offset)?;

                    Some(if msg.flags
                        .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
                    {
                        parse_lm_response_v2(data)
                    } else {
                        parse_lm_response_v1(data)
                    }.to_full_result()
                        .map_err(NtlmError::from)?)
                } else {
                    None
                };

                msg.nt_challenge_response = if nt_challenge_response_field.length > 0 {
                    debug!(
                        "extract LM challenge response at {} with {} bytes, current offset {}",
                        nt_challenge_response_field.offset, nt_challenge_response_field.length, offset
                    );

                    let data = nt_challenge_response_field.extract_data(remaining, offset)?;

                    Some(if msg.flags
                        .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
                    {
                        parse_nt_response_v2(data)
                    } else {
                        parse_nt_response_v1(data)
                    }.to_full_result()
                        .map_err(NtlmError::from)?)
                } else {
                    None
                };

                msg.domain_name = Cow::from(domain_name_field.extract_data(remaining, offset)?);
                msg.user_name = Cow::from(user_name_field.extract_data(remaining, offset)?);
                msg.workstation_name = Cow::from(workstation_name_field.extract_data(remaining, offset)?);

                if msg.flags
                    .contains(NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH)
                    && session_key_field.length > 0
                {
                    msg.session_key = Some(Cow::from(session_key_field.extract_data(remaining, offset)?))
                }

                Ok(msg)
            }
            nom::IResult::Error(err) => bail!(NtlmError::from(err)),
            nom::IResult::Incomplete(needed) => bail!(NtlmError::from(needed)),
        }
    }
}

impl<'a> ToWire for AuthenticateMessage<'a> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
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

        response_offset += self.session_key.write_field(buf, response_offset)?;

        let mut flags = self.flags;

        if self.session_key.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH;
        }

        if self.version.is_some() {
            flags |= NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION;
        }

        buf.put_u32::<LittleEndian>(flags.bits());

        if let Some(ref version) = self.version {
            version.to_wire(buf)?;
        }

        if let Some(ref mic) = self.mic {
            buf.put_slice(mic);
        }

        self.domain_name.to_wire(buf)?;
        self.user_name.to_wire(buf)?;
        self.workstation_name.to_wire(buf)?;

        self.lm_challenge_response.to_wire(buf)?;
        self.nt_challenge_response.to_wire(buf)?;

        self.session_key.to_wire(buf)?;

        Ok(response_offset)
    }
}

const kSignature: &[u8] = b"NTLMSSP\0";
const kSignatureSize: usize = 8;
const kMesssageTypeSize: usize = 4;
const kFlagsSize: usize = 4;
const kFieldSize: usize = 8;
const kVersionSize: usize = 8;
const kMICSize: usize = 16;
const kChallengeSize: usize = 8;
const kReservedSize: usize = 8;
const kAvIdSize: usize = 2;
const kAvLenSize: usize = 2;
const kNtlmClientChalengeHeaderSize: usize = 8;
const kTimestampSize: usize = 8;
const kFileTimeSize: usize = 8;

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
    parse_single_host_data<SingleHostData>,
    do_parse!(
        _size: call!(nom::le_u32) >>
        _reserved: take!(4) >>
        custom_data: call!(nom::le_u64) >>
        machine_id: map!(take!(32), Cow::from) >>
        (SingleHostData { custom_data, machine_id })
    )
);

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
        (
            NegotiateMessage {
                flags,
                domain_name: None,
                workstation_name: None,
                version: None,
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
        server_challenge: map!(take!(8), Cow::from) >>
        _reserved: take!(8) >>
        target_info_field: call!(parse_field) >>
        (
            ChallengeMessage {
                flags,
                server_challenge,
                target_name: None,
                target_info: None,
                version: None,
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
        session_key_field: call!(parse_field) >>
        flags: map!(nom::le_u32, NegotiateFlags::from_bits_truncate) >>
        (
            AuthenticateMessage {
                lm_challenge_response: None,
                nt_challenge_response: None,
                domain_name: Default::default(),
                user_name: Default::default(),
                workstation_name: Default::default(),
                session_key: Default::default(),
                flags,
                version: None,
                mic: None,
            },
            lm_challenge_response_field,
            nt_challenge_response_field,
            domain_name_field,
            user_name_field,
            workstation_name_field,
            session_key_field
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

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_ntlm_client_challenge<NtlmClientChalenge>,
    do_parse!(
        _resp_type: verify!(call!(nom::le_u8), |v| v == 1) >>
        _hi_resp_type: verify!(call!(nom::le_u8), |v| v == 1) >>
        _reserved1: take!(2) >>
        _reserved2: take!(4) >>
        timestamp: map!(call!(nom::le_u64), FileTime::from) >>
        challenge_from_client: map!(take!(8), Cow::from) >>
        _reserved3: take!(4) >>
        target_info: parse_av_pairs >>
        (NtlmClientChalenge {
            timestamp,
            challenge_from_client,
            target_info,
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
            .ok_or(NtlmError::BufferOverflow)?;
        let end = start
            .checked_add(self.length as usize)
            .ok_or(NtlmError::BufferOverflow)?;

        if start >= payload.len() || end > payload.len() {
            bail!(NtlmError::BufferOverflow);
        }

        Ok(&payload[start..end])
    }
}

pub trait FromWire<'a> {
    type Type;

    fn from_wire(payload: &'a [u8]) -> Result<Self::Type, Error>;
}

pub trait ToWire {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error>;
}

impl<T: ToWire> ToWire for Option<T> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        if let Some(ref data) = *self {
            data.to_wire(buf)
        } else {
            Ok(0)
        }
    }
}

impl<'a> ToWire for Cow<'a, [u8]> {
    fn to_wire<B: BufMut>(&self, buf: &mut B) -> Result<usize, Error> {
        buf.put_slice(self.as_ref());

        Ok(self.as_ref().len())
    }
}

trait WriteField {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error>;
}

impl<T: WriteField> WriteField for Option<T> {
    fn write_field<B: BufMut>(&self, buf: &mut B, offset: usize) -> Result<usize, Error> {
        if let Some(ref data) = *self {
            data.write_field(buf, offset)
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

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_field<Field>,
    do_parse!(
        length: call!(nom::le_u16) >>
        capacity: call!(nom::le_u16) >>
        offset: call!(nom::le_u32) >>
        (Field {
            length,
            capacity,
            offset,
        })
    )
);

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    parse_version<Version>,
    do_parse!(
        major: call!(nom::le_u8) >>
        minor: call!(nom::le_u8) >>
        build: call!(nom::le_u16) >>
        _reserved: take!(3) >>
        revision: call!(nom::le_u8) >>
        (Version {
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

    const kUsername: &str = "User";
    const kPassword: &str = "Password";
    const kDomain: &str = "Domain";
    const kServer: &str = "Server";
    const kWorkstation: &str = "COMPUTER";

    lazy_static! {
        static ref kRandomSessionKey: SessionKey = SessionKey::from_iter(iter::repeat(0x55).take(16));
        static ref kTime: FileTime = FileTime::from(0);
        static ref kChallengeFlags: NegotiateFlags = NegotiateFlags::NTLMSSP_NEGOTIATE_KEY_EXCH
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_56
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_128
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION
                                                    | NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_SEAL
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_SIGN
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;
        static ref kClientChallengeFlags: NegotiateFlags = NegotiateFlags::NTLMSSP_NEGOTIATE_56
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_VERSION
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                                                    | NegotiateFlags::NTLMSSP_TARGET_TYPE_SERVER
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_SEAL
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_SIGN
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM
                                                    | NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE;
        static ref kClientChallenge: ClientChallenge = arr![u8; 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
        static ref kServerChallenge: ServerChallenge = arr![u8; 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        static ref kSessionBaseKey: SessionKey = arr![u8; 0xd8, 0x72, 0x62, 0xb0, 0xcd, 0xe4, 0xb1, 0xcb,
                                                          0x74, 0x99, 0xbe, 0xcc, 0xcd, 0xf1, 0x07, 0x84];
        static ref  kNtChallengeResponseV1: GenericArray<u8, U24> = arr![u8;
            0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2, 0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16, 0x33, 0x1c, 0x44, 0xbd,
            0xbe, 0xd9, 0x27, 0x84, 0x1f, 0x94
        ];

        static ref kLmChallengeResponseV1: GenericArray<u8, U24> = arr![u8;
            0x98, 0xde, 0xf7, 0xb8, 0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88, 0xa1, 0x72, 0xde, 0xf1,
            0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13
        ];
    }

    #[test]
    fn ntlm_v1_authentication() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            nt_owf_v1(kPassword).as_slice(),
            &[
                0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52
            ][..]
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            lm_owf_v1(kPassword).as_slice(),
            &[
                0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22, 0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6, 0xcb, 0x6d
            ][..]
        );

        let nt_response_key = nt_owf_v1(kPassword);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            generate_session_base_key_v1(&nt_response_key),
            *kSessionBaseKey
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            NtChallengeResponse::v1(&nt_response_key, &*kServerChallenge),
            NtChallengeResponse::V1 {
                response: kNtChallengeResponseV1.as_slice().into(),
            }
        );

        let lm_response_key = lm_owf_v1(kPassword);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            LmChallengeResponse::v1(&lm_response_key, &*kServerChallenge),
            LmChallengeResponse::V1 {
                response: kLmChallengeResponseV1.as_slice().into(),
            }
        );
    }

    #[test]
    fn key_exchange_key() {
        let lm_response_key = lm_owf_v1(kPassword);
        let key = generate_key_exchange_key(
            *kChallengeFlags,
            &lm_response_key,
            &*kSessionBaseKey,
            &*kServerChallenge,
            GenericArray::from_slice(&kLmChallengeResponseV1.as_slice()[..8]),
        );
        let buf = rc4(&key, &*kRandomSessionKey).unwrap();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            buf.as_slice(),
            &[
                0x51, 0x88, 0x22, 0xb1, 0xb3, 0xf3, 0x50, 0xc8, 0x95, 0x86, 0x82, 0xec, 0xbb, 0x3e, 0x3c, 0xb7
            ][..]
        );
    }

    #[test]
    fn key_exchange_key_with_lm_key() {
        let lm_response_key = lm_owf_v1(kPassword);
        let key = generate_key_exchange_key(
            *kChallengeFlags | NegotiateFlags::NTLMSSP_NEGOTIATE_LM_KEY,
            &lm_response_key,
            &*kSessionBaseKey,
            &*kServerChallenge,
            GenericArray::from_slice(&kLmChallengeResponseV1.as_slice()[..8]),
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            key.as_slice(),
            &[
                0xb0, 0x9e, 0x37, 0x9f, 0x7f, 0xbe, 0xcb, 0x1e, 0xaf, 0x0a, 0xfd, 0xcb, 0x03, 0x83, 0xc8, 0xa0
            ][..]
        );

        let buf = rc4(&key, &*kRandomSessionKey).unwrap();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            buf.as_slice(),
            &[
                0x4c, 0xd7, 0xbb, 0x57, 0xd6, 0x97, 0xef, 0x9b, 0x54, 0x9f, 0x02, 0xb8, 0xf9, 0xb3, 0x78, 0x64
            ][..]
        );
    }

    #[test]
    fn key_exchange_key_with_request_non_nt_session_key() {
        let lm_response_key = lm_owf_v1(kPassword);
        let key = generate_key_exchange_key(
            *kChallengeFlags | NegotiateFlags::NTLMSSP_REQUEST_NON_NT_SESSION_KEY,
            &lm_response_key,
            &*kSessionBaseKey,
            &*kServerChallenge,
            GenericArray::from_slice(&kLmChallengeResponseV1.as_slice()[..8]),
        );
        let buf = rc4(&key, &*kRandomSessionKey).unwrap();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            buf.as_slice(),
            &[
                0x74, 0x52, 0xca, 0x55, 0xc2, 0x25, 0xa1, 0xca, 0x04, 0xb4, 0x8f, 0xae, 0x32, 0xcf, 0x56, 0xfc
            ][..]
        );
    }

    #[test]
    fn ntlm_v1_authentication_with_client_challenge() {
        let mut lm_challenge_response = kClientChallenge.as_slice().to_vec();

        lm_challenge_response.append(&mut vec![0u8; 16]);

        let lm_response_key = lm_owf_v1(kPassword);
        let key_exchange_key = generate_key_exchange_key(
            *kClientChallengeFlags,
            &lm_response_key,
            &*kSessionBaseKey,
            &*kServerChallenge,
            GenericArray::from_slice(&lm_challenge_response[..8]),
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            key_exchange_key.as_slice(),
            &[
                0xeb, 0x93, 0x42, 0x9a, 0x8b, 0xd9, 0x52, 0xf8, 0xb8, 0x9c, 0x55, 0xb8, 0x7f, 0x47, 0x5e, 0xdc
            ][..]
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            generate_seal_key(
                *kClientChallengeFlags,
                &key_exchange_key,
                false,
                0,
            ).as_slice(),
            &[
                0x04, 0xdd, 0x7f, 0x01, 0x4d, 0x85, 0x04, 0xd2, 0x65, 0xa2, 0x5c, 0xc8, 0x6a, 0x3a, 0x7c, 0x06
            ][..]
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            generate_sign_key(*kClientChallengeFlags, &key_exchange_key, false).unwrap().as_slice(),
            &[
                0x60, 0xe7, 0x99, 0xbe, 0x5c, 0x72, 0xfc, 0x92, 0x92, 0x2a, 0xe8, 0xeb, 0xe9, 0x61, 0xfb, 0x8d
            ][..]
        );
    }

    #[test]
    fn ntlm_v2_authentication() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            nt_owf_v2(kUsername, kPassword, kDomain).as_slice(),
            &[
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
            ][..]
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        assert_eq!(
            lm_owf_v2(kUsername, kPassword, kDomain).as_slice(),
            &[
                0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f
            ][..]
        );

        let nt_response_key = nt_owf_v2(kUsername, kPassword, kDomain);

        let nt_challenge_response = NtChallengeResponse::v2(
            &nt_response_key,
            &*kServerChallenge,
            &*kClientChallenge,
            *kTime,
            vec![nb_domain_name(kDomain), nb_computer_name(kServer)],
        );

        #[cfg_attr(rustfmt, rustfmt_skip)]
        const client_challenge: &[u8] = &[
            // RespType (1 byte):
            0x01,
            // HiRespType (1 byte):
            0x01,
            // Reserved1 (2 bytes):
            0x00, 0x00,
            // Reserved2 (4 bytes):
            0x00, 0x00, 0x00, 0x00,
            // TimeStamp (8 bytes):
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // ChallengeFromClient (8 bytes):
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            // Reserved3 (4 bytes):
            0x00, 0x00, 0x00, 0x00,
            // AvPairs (variable):
            // MsvAvNbDomainName (Domain)
            //   AvId (2 bytes):
            0x02, 0x00,
            //   AvLen (2 bytes):
            0x0c, 0x00,
            //   Value (variable):
            0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            // MsvAvNbComputerName (Server)
            //   AvId (2 bytes):
            0x01, 0x00,
            //   AvLen (2 bytes):
            0x0c, 0x00,
            //   Value (variable):
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
            // NbEOL
            0x00, 0x00, 0x00, 0x00,
            // Reserved
            0x00, 0x00, 0x00, 0x00
        ];

        match nt_challenge_response {
            NtChallengeResponse::V2 {
                ref response,
                ref challenge,
            } => {
                assert_eq!(
                    response.as_ref(),
                    &[
                        0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef, 0x6a, 0x1c
                    ][..]
                );

                let mut buf = vec![];

                assert_eq!(challenge.to_wire(&mut buf).unwrap(), client_challenge.len());
                assert_eq!(buf.as_slice(), client_challenge);
            }
            _ => panic!(),
        }
        let nt_response = nt_challenge_response.response();
        let nt_proof_str = GenericArray::from_slice(nt_response.as_ref());

        assert_eq!(
            generate_session_base_key_v2(&nt_response_key, nt_proof_str).as_slice(),
            &[
                0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9, 0x5c, 0xa3
            ][..]
        );

        let lm_response_key = lm_owf_v2(kUsername, kPassword, kDomain);
        let lm_response = LmChallengeResponse::v2(&lm_response_key, &*kServerChallenge, &*kClientChallenge);

        assert_eq!(
            lm_response,
            LmChallengeResponse::V2 {
                response: (&[
                    0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19
                ][..])
                    .into(),
                challenge: (&[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA][..]).into(),
            }
        );
    }

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

        #[cfg_attr(rustfmt, rustfmt_skip)]
        let message = NegotiateMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLMSSP_NEGOTIATE_OEM
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

        assert_eq!(NegotiateMessage::from_wire(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.to_wire(&mut buf).unwrap(), packet.len());
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

        #[cfg_attr(rustfmt, rustfmt_skip)]
        let message = ChallengeMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM
                | NegotiateFlags::NTLMSSP_TARGET_TYPE_DOMAIN
                | NegotiateFlags::NTLMSSP_NEGOTIATE_TARGET_INFO,
            server_challenge: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].into(),
            target_name: Some(utf16("DOMAIN").into()),
            target_info: Some(vec![
                nb_domain_name("DOMAIN"),
                nb_computer_name("SERVER"),
                dns_domain_name("domain.com"),
                dns_computer_name("server.domain.com"),
                eol(),
            ]),
            version: None,
        };

        assert_eq!(ChallengeMessage::from_wire(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.to_wire(&mut buf).unwrap(), packet.len());
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

        #[cfg_attr(rustfmt, rustfmt_skip)]
        let message = AuthenticateMessage {
            flags: NegotiateFlags::NTLMSSP_NEGOTIATE_UNICODE | NegotiateFlags::NTLMSSP_NEGOTIATE_NTLM,
            lm_challenge_response: Some(LmChallengeResponse::V1 {
                response: Cow::from(vec![
                    0xc3, 0x37, 0xcd, 0x5c, 0xbd, 0x44, 0xfc, 0x97, 0x82, 0xa6, 0x67, 0xaf, 0x6d, 0x42, 0x7c, 0x6d,
                    0xe6, 0x7c, 0x20, 0xc2, 0xd3, 0xe7, 0x7c, 0x56,
                ]),
            }),
            nt_challenge_response: Some(NtChallengeResponse::V1 {
                response: Cow::from(vec![
                    0x25, 0xa9, 0x8c, 0x1c, 0x31, 0xe8, 0x18, 0x47, 0x46, 0x6b, 0x29, 0xb2, 0xdf, 0x46, 0x80, 0xf3,
                    0x99, 0x58, 0xfb, 0x8c, 0x21, 0x3a, 0x9c, 0xc6,
                ]),
            }),
            domain_name: utf16("DOMAIN").into(),
            user_name: utf16("user").into(),
            workstation_name: utf16("WORKSTATION").into(),
            session_key: None,
            version: None,
            mic: None,
        };

        assert_eq!(AuthenticateMessage::from_wire(packet).unwrap(), message);

        let mut buf: Vec<u8> = vec![];

        assert_eq!(message.to_wire(&mut buf).unwrap(), packet.len());
        assert_eq!(buf.as_slice(), packet);
    }
}
