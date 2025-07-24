use thiserror::Error;
use crate::ingester::parser::state_update::SequenceGap;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum IngesterError {
    #[error("Persist logic for {event_type} has not yet been implemented")]
    EventNotImplemented { event_type: String },
    #[error("Malformed event: {msg}")]
    MalformedEvent { msg: String },
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Parser error: {0}")]
    ParserError(String),
    #[error("Empty batch event.")]
    EmptyBatchEvent,
    #[error("Invalid event.")]
    InvalidEvent,
    #[error("Sequence gap detected: {} gaps found", .0.len())]
    SequenceGapDetected(Vec<SequenceGap>),
}

impl From<sea_orm::error::DbErr> for IngesterError {
    fn from(err: sea_orm::error::DbErr) -> Self {
        IngesterError::DatabaseError(format!("DatabaseError: {}", err))
    }
}

impl From<String> for IngesterError {
    fn from(err: String) -> Self {
        IngesterError::ParserError(err)
    }
}

impl From<crate::ingester::parser::state_update::SequenceGapError> for IngesterError {
    fn from(err: crate::ingester::parser::state_update::SequenceGapError) -> Self {
        match err {
            crate::ingester::parser::state_update::SequenceGapError::GapDetected(gaps) => {
                IngesterError::SequenceGapDetected(gaps)
            }
        }
    }
}
