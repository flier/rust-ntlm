#![allow(non_upper_case_globals)]

use std::borrow::Cow;
use std::iter::{self, FromIterator};

use byteorder::LittleEndian;
use bytes::BufMut;

use failure::Error;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U24, U7, U8};
use itertools;
use rand::{thread_rng, Rng};

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
use proto::{eol, AvId, AvPair, FileTime, NTLMSSP_REVISION_W2K3, NegotiateFlags, ToWire, WriteField, utf16};

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
            timestamp: current_time,
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

const kNtlmClientChalengeHeaderSize: usize = 8;
const kTimestampSize: usize = 8;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

#[cfg(test)]
mod tests {
    use super::*;

    use proto::{nb_computer_name, nb_domain_name};

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
}
