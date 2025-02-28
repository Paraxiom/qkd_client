// src/byzantine/mod.rs
pub mod buffer;
pub mod consensus;
pub mod manager;
pub mod vrf_consensus;
pub use buffer::{ConsensusMessage, MessageType, ReporterEntry, SharedBuffer};
pub use consensus::{ByzantineConsensus, ConsensusConfig, ConsensusResult};
pub use manager::{ReportResult, ReporterManager};
