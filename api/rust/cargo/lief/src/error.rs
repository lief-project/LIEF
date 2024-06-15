use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    ReadError,
    NotFound,
    NotImplemented,
    NotSupported,
    Corrupted,
    ConversionError,
    ReadOutOfBound,
    ASN1BadTag,
    FileError,
    FileFormatError,
    ParsingError,
    BuildError,
    DataTooLarge,
    Unknown(u32),
}

impl From<u32> for Error {
    fn from(value: u32) -> Self {
        match value {
            0x00000001 => Error::ReadError,
            0x00000002 => Error::NotFound,
            0x00000003 => Error::NotImplemented,
            0x00000004 => Error::NotSupported,
            0x00000005 => Error::Corrupted,
            0x00000006 => Error::ConversionError,
            0x00000007 => Error::ReadOutOfBound,
            0x00000008 => Error::ASN1BadTag,
            0x00000009 => Error::FileError,
            0x0000000a => Error::FileFormatError,
            0x0000000b => Error::ParsingError,
            0x0000000c => Error::BuildError,
            0x0000000d => Error::DataTooLarge,
            _ => Error::Unknown(value),

        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LIEF Error Occurred!")
    }
}
