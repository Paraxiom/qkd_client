// src/zk/multi_source_generator.rs
use std::error::Error;
use std::sync::Arc;
use tracing::{debug, info};

use crate::byzantine::buffer::{SharedBuffer, ReporterEntry};
use crate::byzantine::consensus::{ByzantineConsensus, ConsensusResult};
use crate::zk::multi_source_proof::MultiSourceKeyProof;
use crate::zk::vrf::VerifiableRandomFunction;

/// Generator for multi-source proofs from Byzantine consensus
pub struct MultiSourceProofGenerator {
    buffer: Arc<SharedBuffer>,
    threshold: usize,
}

/// Result of the multi-source proof generation
pub struct MultiSourceProofResult {
    pub proof: MultiSourceKeyProof,
    pub vrf: VerifiableRandomFunction,
    pub source_count: usize,
    pub consensus_result: ConsensusResult,
}

impl MultiSourceProofGenerator {
    /// Create a new multi-source proof generator
    pub fn new(buffer: Arc<SharedBuffer>, threshold: usize) -> Self {
        Self {
            buffer,
            threshold,
        }
    }
    
    /// Generate a proof from the current state of the buffer
    pub async fn generate_proof(&self) -> Result<MultiSourceProofResult, Box<dyn Error>> {
        // Get all reports from the buffer
        let reports = self.buffer.get_all_reports();
        if reports.is_empty() {
            return Err("No reports available for proof generation".into());
        }
        
        info!("Generating multi-source proof from {} reports", reports.len());
        
        // Create multi-source proof
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
            
        let proof = MultiSourceKeyProof::new(
            &reports, 
            self.threshold,
            nonce
        ).await?;
        
        // Create a VRF from the proof commitment and seed
        let vrf = VerifiableRandomFunction::from_multi_source_proof(
            proof.get_commitment(),
            proof.get_vrf_seed()
        )?;
        
        // Create a placeholder consensus result (in a real implementation,
        // this would be the actual result from running Byzantine consensus)
        let consensus_result = ConsensusResult {
            success: true,
            value: Some(proof.get_commitment().as_bytes().to_vec()),
            reporter_ids: reports.iter().map(|r| r.reporter_id.clone()).collect(),
            round_duration: std::time::Duration::from_secs(0),
            round_number: 0,
            total_messages: reports.len(),
        };
        
        Ok(MultiSourceProofResult {
            proof,
            vrf,
            source_count: reports.len(),
            consensus_result,
        })
    }
    
    /// Generate proof after running Byzantine consensus
    pub async fn generate_proof_with_consensus(
        &self,
        consensus: &ByzantineConsensus
    ) -> Result<MultiSourceProofResult, Box<dyn Error>> {
        // Run Byzantine consensus
        info!("Running Byzantine consensus before generating proof");
        let consensus_result = if consensus.is_primary() {
            // If we're the primary, start a new consensus round
            let value = b"Start multi-source proof generation".to_vec();
            consensus.start_consensus(value)?;
            
            // Wait for consensus (in a real system, would properly manage state)
            std::thread::sleep(std::time::Duration::from_secs(1));
            
            // Create placeholder result
            ConsensusResult {
                success: true,
                value: Some(b"Primary initiated consensus".to_vec()),
                reporter_ids: vec![],
                round_duration: std::time::Duration::from_secs(1),
                round_number: 0,
                total_messages: 0,
            }
        } else {
            // Not primary, participate in consensus
            consensus.run_consensus_round()?
        };
        
        // Only proceed if consensus was successful
        if !consensus_result.success {
            return Err("Byzantine consensus failed, cannot generate proof".into());
        }
        
        // Generate proof from reports
        let proof_result = self.generate_proof().await?;
        
        // Combine with consensus result
        Ok(MultiSourceProofResult {
            proof: proof_result.proof,
            vrf: proof_result.vrf,
            source_count: proof_result.source_count,
            consensus_result,
        })
    }
    
    /// Add a report to the buffer
    pub fn add_report(&self, report: ReporterEntry) {
        self.buffer.add_report(report);
    }
}
