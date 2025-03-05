// src/vrf/qkd_vrf.rs
use crate::qkd::etsi_api::{DeviceType, ETSIClient, Side};
use crate::vrf::core::QuantumVRF;
use std::error::Error;
use std::path::Path;

pub struct QKDVerifiableRandomFunction {
    vrf: QuantumVRF,
    etsi_client: ETSIClient,
}

impl QKDVerifiableRandomFunction {
    pub fn new(
        vrf: QuantumVRF,
        device_type: DeviceType,
        cert_path: &Path,
    ) -> Result<Self, Box<dyn Error>> {
        // For a VRF implementation, we'll use Alice as the default side
        // Alice is typically the key generator in QKD protocols
        let side = Side::Alice;

        let etsi_client = ETSIClient::new(device_type, side, cert_path, None, None)?;

        Ok(Self { vrf, etsi_client })
    }

    // Generate VRF output using quantum key from QKD device
    pub async fn generate_with_qkd(
        &self,
        input: &[u8],
        dest_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, String), Box<dyn Error>> {
        // Get quantum key from QKD device
        let qkd_key = self.etsi_client.get_key_alice(32, dest_id, None).await?;

        // Use the quantum key as input for the VRF
        let (output, proof) = self.vrf.generate(input, &qkd_key.key_bytes)?;

        // Return output, proof, and key_id for verification
        Ok((output, proof, qkd_key.key_id))
    }

    // Verify VRF output using quantum key from QKD device
    pub async fn verify_with_qkd(
        &self,
        input: &[u8],
        output: &[u8],
        proof: &[u8],
        key_id: &str,
    ) -> Result<bool, Box<dyn Error>> {
        // Get quantum key from QKD device (Bob's side)
        let qkd_key = self.etsi_client.get_key_bob(key_id).await?;

        // Verify the VRF output using the quantum key
        let is_valid = self.vrf.verify(input, output, proof, &qkd_key.key_bytes)?;

        // Optionally delete the key after use for security
        if is_valid {
            // Only attempt to delete if verification was successful
            let _ = self.etsi_client.delete_key(key_id).await;
        }

        Ok(is_valid)
    }

    // Get the available quantum key size from the QKD device
    pub async fn get_available_key_size(&self) -> Result<usize, Box<dyn Error>> {
        self.etsi_client.get_available_key_size().await
    }
}
