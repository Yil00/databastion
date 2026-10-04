//! Audit from the CAS JSON audit log (ADR-0041 decisions 7, 8 and 10):
//! the record-to-event conversion ([`events`]), the level rule
//! ([`level`]) and the incremental reader ([`stream`]).

pub mod events;
pub mod level;
pub mod stream;
