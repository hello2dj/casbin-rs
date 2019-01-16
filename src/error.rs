
use std::io;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotImplemented,
    UnsupportedEffect,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::UnsupportedEffect => write!(f, "Unsupported effect"),
        }
    }
}
