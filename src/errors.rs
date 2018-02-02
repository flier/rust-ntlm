use failure;
use nom;
use num::FromPrimitive;

#[derive(Debug, Fail)]
pub enum NtlmError {
    #[fail(display = "incomlete message, {:?}", _0)] IncompleteMessage(nom::Needed),

    #[fail(display = "invalid message, {:?}", _0)] InvalidMessage(nom::ErrorKind),

    #[fail(display = "message signature mismatched")] MismatchedSignature,

    #[fail(display = "message offset overflow")] OffsetOverflow,
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
}
