use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    FileRead,
    FileWrite,
    NotImplemented,
    UnsupportedEffect,
    // Temporary error type, we probably want more specific errors when we fail to parse.
    ParsingFailure,
    MissingKey,
    InvalidValue,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::FileRead => write!(f, "File read error"),
            Error::FileWrite => write!(f, "File write error"),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::UnsupportedEffect => write!(f, "Unsupported effect"),
            Error::ParsingFailure => write!(f, "Parsing failure"),
            Error::MissingKey => write!(f, "Missing key in configuration"),
            Error::InvalidValue => write!(f, "Invalid value in configuration"),
        }
    }
}
