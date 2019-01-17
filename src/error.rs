use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnsupportedEffect,
    // Temporary error type, we probably want more specific errors when we fail to parse.
    ParsingFailure,
    MissingKey,
    InvalidValue,
    MissingRole(String),
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
            Error::UnsupportedEffect => write!(f, "Unsupported effect"),
            Error::ParsingFailure => write!(f, "Parsing failure"),
            Error::MissingKey => write!(f, "Missing key in configuration"),
            Error::InvalidValue => write!(f, "Invalid value in configuration"),
            Error::MissingRole(ref name) => write!(f, "Missing role {}", name),
        }
    }
}
