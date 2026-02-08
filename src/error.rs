use anyhow::anyhow;

pub type Result<T> = std::result::Result<T, LibError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Database,
    Forbidden,
    InvalidInput,
    NotFound,
    Unknown,
}

#[derive(Debug)]
pub struct LibError {
    pub kind: ErrorKind,
    pub public: &'static str,
    pub source: anyhow::Error,
}

impl LibError {
    pub fn database(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Database,
            public,
            source,
        }
    }

    pub fn invalid(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            public,
            source,
        }
    }

    pub fn forbidden(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Forbidden,
            public,
            source,
        }
    }

    pub fn not_found(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            public,
            source,
        }
    }

    pub fn unknown(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Unknown,
            public,
            source,
        }
    }

    pub fn message(public: &'static str) -> Self {
        Self::unknown(public, anyhow!(public))
    }
}

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for LibError {
    fn from(value: sqlx::Error) -> Self {
        Self::database("Database request failed", anyhow!(value))
    }
}
