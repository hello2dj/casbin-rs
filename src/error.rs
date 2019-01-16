
use std::io;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    FileRead,
    FileWrite,
    NotImplemented,
    UnsupportedEffect,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::FileRead => write!(f, "File read error"),
            Error::FileWrite => write!(f, "File write error"),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::UnsupportedEffect => write!(f, "Unsupported effect"),
        }
    }
}
