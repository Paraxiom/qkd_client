use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ff::Field;

#[derive(Default)]
pub struct MyCircuit {
    // If you need circuit fields, add them here
}

impl<F: Field> ConstraintSynthesizer<F> for MyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // For a dummy circuit, do nothing:
        Ok(())
    }
}

