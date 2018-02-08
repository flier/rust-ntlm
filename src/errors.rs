use std::error::Error;
use std::str;
use std::sync;

use crypto::symmetriccipher::SymmetricCipherError;
use nom;
use num::FromPrimitive;

use proto::NegotiateFlags;

#[derive(Debug, Fail)]
pub enum NtlmError {
    #[fail(display = "incomlete message, {:?}", _0)] IncompleteMessage(nom::Needed),

    #[fail(display = "invalid message, {:?}", _0)] InvalidMessage(nom::ErrorKind),

    #[fail(display = "message signature mismatched")] MismatchedSignature,

    #[fail(display = "message type mismatched")] MismatchedMsgType,

    #[fail(display = "unexpected message")] UnexpectedMessage,

    #[fail(display = "unsupported function, {:?}", _0)] UnsupportedFunction(NegotiateFlags),

    #[fail(display = "logon failure")] LogonFailure,

    #[fail(display = "buffer overflow")] BufferOverflow,

    #[fail(display = "symmetric cipher error, {:?}", _0)] SymmetricCipher(SymmetricCipherError),

    #[fail(display = "fail to decode UTF-8, {:?}", _0)] Utf8Error(#[cause] str::Utf8Error),

    #[fail(display = "fail to decode UTF-16")] Utf16Error,

    #[fail(display = "fail to lock mutex, {}", _0)] LockError(String),
}

impl<I> From<nom::IError<I>> for NtlmError {
    fn from(err: nom::IError<I>) -> Self {
        match err {
            nom::IError::Error(err) => NtlmError::from(err.into_error_kind()),
            nom::IError::Incomplete(needed) => NtlmError::from(needed),
        }
    }
}

impl<P> From<nom::Err<P>> for NtlmError {
    fn from(err: nom::Err<P>) -> Self {
        NtlmError::from(err.into_error_kind())
    }
}

impl From<nom::Needed> for NtlmError {
    fn from(needed: nom::Needed) -> Self {
        NtlmError::IncompleteMessage(needed)
    }
}

impl From<nom::ErrorKind> for NtlmError {
    fn from(err: nom::ErrorKind) -> Self {
        match err {
            nom::ErrorKind::Custom(code) => match ParseError::from_u32(code) {
                Some(ParseError::MismatchedSignature) => NtlmError::MismatchedSignature,
                Some(ParseError::MismatchedMsgType) => NtlmError::MismatchedMsgType,
                None => NtlmError::InvalidMessage(err),
            },
            _ => NtlmError::InvalidMessage(err),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq)]
pub enum ParseError {
    MismatchedSignature,
    MismatchedMsgType,
}

impl From<SymmetricCipherError> for NtlmError {
    fn from(err: SymmetricCipherError) -> Self {
        NtlmError::SymmetricCipher(err)
    }
}

impl From<str::Utf8Error> for NtlmError {
    fn from(err: str::Utf8Error) -> Self {
        NtlmError::Utf8Error(err)
    }
}

impl<T> From<sync::PoisonError<T>> for NtlmError {
    fn from(err: sync::PoisonError<T>) -> Self {
        NtlmError::LockError(err.description().to_owned())
    }
}
