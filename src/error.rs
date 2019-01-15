
use std::io;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    UnsupportedEffect,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::UnsupportedEffect => write!(f, "Unsupported Effect"),
        }
    }
}
