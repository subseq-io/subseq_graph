use anyhow::anyhow;
use subseq_auth::prelude::ApiErrorDetails;

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
    pub code: &'static str,
    pub public: &'static str,
    pub details: Option<ApiErrorDetails>,
    pub source: anyhow::Error,
}

impl LibError {
    pub fn database(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Database,
            code: "database_error",
            public,
            details: None,
            source,
        }
    }

    pub fn invalid(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            code: "invalid_input",
            public,
            details: None,
            source,
        }
    }

    pub fn invalid_with_code(
        code: &'static str,
        public: &'static str,
        source: anyhow::Error,
    ) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            code,
            public,
            details: None,
            source,
        }
    }

    pub fn forbidden(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Forbidden,
            code: "forbidden",
            public,
            details: None,
            source,
        }
    }

    pub fn forbidden_missing_scope(
        public: &'static str,
        scope: &str,
        scope_id: String,
        required_any_roles: Vec<String>,
        source: anyhow::Error,
    ) -> Self {
        Self {
            kind: ErrorKind::Forbidden,
            code: "missing_scope_check",
            public,
            details: Some(ApiErrorDetails::MissingScopeCheck {
                scope: scope.to_string(),
                scope_id,
                required_any_roles,
            }),
            source,
        }
    }

    pub fn not_found(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            code: "not_found",
            public,
            details: None,
            source,
        }
    }

    pub fn unknown(public: &'static str, source: anyhow::Error) -> Self {
        Self {
            kind: ErrorKind::Unknown,
            code: "unknown_error",
            public,
            details: None,
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
