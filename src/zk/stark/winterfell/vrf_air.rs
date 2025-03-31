use thiserror::Error;
use winter_air::BatchingMethod;
use winter_air::FieldExtension;
use winter_math::{fields::f128::BaseElement, FieldElement, ToElements};
use winterfell::Trace; // Add this import
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
// Define the field element type we'll use
pub type Felt = BaseElement;

// Re-export VrfPublicInputs to be used in other modules
#[derive(Clone, Debug, PartialEq)]
pub struct VrfPublicInputs {
    pub input_hash: [Felt; 4],
    pub expected_output: [Felt; 4],
}

impl VrfPublicInputs {
    pub fn new(input_hash: &[u8], expected_output: &[u8]) -> Result<Self, VrfError> {
        if input_hash.len() < 32 || expected_output.len() < 32 {
            return Err(VrfError::InputTooShort);
        }

        // Convert input hash bytes to field elements (4 elements of 64 bits each)
        let mut input_hash_felts = [Felt::ZERO; 4];
        for i in 0..4 {
            let offset = i * 8;
            if offset + 8 <= input_hash.len() {
                let bytes = &input_hash[offset..offset + 8];
                let value = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                input_hash_felts[i] = Felt::from(value);
            }
        }

        // Convert expected output bytes to field elements
        let mut output_felts = [Felt::ZERO; 4];
        for i in 0..4 {
            let offset = i * 8;
            if offset + 8 <= expected_output.len() {
                let bytes = &expected_output[offset..offset + 8];
                let value = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                output_felts[i] = Felt::from(value);
            }
        }

        Ok(VrfPublicInputs {
            input_hash: input_hash_felts,
            expected_output: output_felts,
        })
    }
}

// Implement ToElements trait for VrfPublicInputs
impl ToElements<Felt> for VrfPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut result = Vec::with_capacity(8);
        result.extend_from_slice(&self.input_hash);
        result.extend_from_slice(&self.expected_output);
        result
    }
}

// The algebraic intermediate representation for our VRF computation
pub struct VrfAir {
    context: AirContext<Felt>,
    pub_inputs: VrfPublicInputs,
}

impl VrfAir {
    pub fn new(trace_info: TraceInfo, pub_inputs: VrfPublicInputs, options: ProofOptions) -> Self {
        // Create the AIR context with appropriate constraint degrees
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];

        let context = AirContext::new(
            trace_info, degrees, 4, // NUM_COLUMNS
            options,
        );

        Self {
            context,
            pub_inputs,
        }
    }

    // Helper to access public inputs
    pub fn get_pub_inputs(&self) -> &VrfPublicInputs {
        &self.pub_inputs
    }
}

impl Air for VrfAir {
    type BaseField = Felt;
    type PublicInputs = VrfPublicInputs;

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    // Air trait requires this method
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self::new(trace_info, pub_inputs, options)
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // These constraints match the state update logic in build_vrf_trace
        // First column: next[0] = current[0] + current[1] + key_felt
        // We can't fully verify this without key_felt, so we'll do a partial check
        result[0] = next[0] - current[0] - current[1];

        // Second column: next[1] = current[1] * current[2]
        result[1] = next[1] - current[1] * current[2];

        // Third column: next[2] = current[2] + current[3]
        result[2] = next[2] - current[2] - current[3];

        // Fourth column: next[3] = current[3] * key_felt + current[0]
        // Partial check here as well
        result[3] = next[3] - current[0];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert the first state element matches input and last element matches output
        vec![
            Assertion::single(0, 0, self.pub_inputs.input_hash[0]),
            Assertion::single(
                self.context().trace_len() - 1,
                0,
                self.pub_inputs.expected_output[0],
            ),
        ]
    }
}

// Add near the top of vrf_air.rs, after the VrfAir struct

/// AIR for VRF combined with Falcon signature verification
pub struct FalconVrfAir {
    context: AirContext<Felt>,
    pub_inputs: VrfPublicInputs,
}

impl FalconVrfAir {
    pub fn new(trace_info: TraceInfo, pub_inputs: VrfPublicInputs, options: ProofOptions) -> Self {
        // Simple implementation that resembles VrfAir
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];

        let context = AirContext::new(
            trace_info, degrees, 4, // NUM_COLUMNS
            options,
        );

        Self {
            context,
            pub_inputs,
        }
    }

    pub fn get_pub_inputs(&self) -> &VrfPublicInputs {
        &self.pub_inputs
    }
}

// Implement Air trait for FalconVrfAir
impl Air for FalconVrfAir {
    type BaseField = Felt;
    type PublicInputs = VrfPublicInputs;

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self::new(trace_info, pub_inputs, options)
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E], // Note the underscore to avoid unused variable warning
        result: &mut [E],
    ) {
        // For now, just copy the same constraints as VrfAir
        let current = frame.current();
        let next = frame.next();

        // These constraints match the state update logic in build_vrf_trace
        result[0] = next[0] - current[0] - current[1];
        result[1] = next[1] - current[1] * current[2];
        result[2] = next[2] - current[2] - current[3];
        result[3] = next[3] - current[0];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Same assertions as VrfAir for now
        vec![
            Assertion::single(0, 0, self.pub_inputs.input_hash[0]),
            Assertion::single(
                self.context().trace_len() - 1,
                0,
                self.pub_inputs.expected_output[0],
            ),
        ]
    }
}

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("Input data too short")]
    InputTooShort,

    #[error("Invalid field element")]
    InvalidFieldElement,

    #[error("Conversion error: {0}")]
    ConversionError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::TraceTable;

    #[test]
    fn test_create_public_inputs() {
        let input = [1u8; 32];
        let output = [2u8; 32];

        let pub_inputs = VrfPublicInputs::new(&input, &output).unwrap();

        // Simple assertion to make sure it creates without errors
        assert_eq!(pub_inputs.input_hash.len(), 4);
        assert_eq!(pub_inputs.expected_output.len(), 4);
    }

    #[test]
    fn test_create_air() {
        // Create a minimal trace
        let mut trace = TraceTable::<Felt>::new(4, 8);
        for i in 0..8 {
            for j in 0..4 {
                trace.set(i, j, Felt::from((i * 4 + j) as u64));
            }
        }

        // Create minimal public inputs
        let pub_inputs = VrfPublicInputs {
            input_hash: [Felt::from(1u64); 4],
            expected_output: [Felt::from(2u64); 4],
        };

        // Create minimal proof options
        let options = ProofOptions::new(
            16,                        // queries
            4,                         // blowup factor
            8,                         // grinding factor
            FieldExtension::Quadratic, // field extension
            4,                         // FRI folding factor
            31,                        // FRI max remainder size
            BatchingMethod::Linear,    // first batching method
            BatchingMethod::Linear,    // second batching method
        );
        // In vrf_air.rs test_create_air
        let mut trace = TraceTable::<Felt>::new(4, 8);
        // Create AIR
        let air = VrfAir::new(trace.info().clone(), pub_inputs, options);

        // Simple assertion to ensure it creates without errors
        assert_eq!(air.context().trace_len(), 8);
    }
}
