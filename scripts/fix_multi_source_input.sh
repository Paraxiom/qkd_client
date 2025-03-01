#!/bin/bash
# fix_multi_source_input.sh - Script to fix the multi-source proof input format

echo "Fixing multi-source input format..."

# Create a correctly formatted input file
cat > circuits/multi_source_input.json << EOL
{
  "sourceCount": 5,
  "validSources": [1, 1, 1, 1, 1, 0, 0, 0]
}
EOL

echo "Updated multi_source_input.json with correct format"

# Now update the multi_source_proof.rs file to generate the correct input format
# First, make a backup
cp src/zk/multi_source_proof.rs src/zk/multi_source_proof.rs.bak

# Find the prepare_input_file function and update it
sed -i '/fn prepare_input_file/,/}/c\
    fn prepare_input_file(\
        sources: \&[ReporterEntry],\
        threshold: usize,\
        nonce: u64\
    ) -> Result<Value, Box<dyn Error>> {\
        // Extract just the needed fields for the circuit\
        let source_count = sources.len() as u64;\
        \
        // Create validSources array with correct size (N from the circuit template)\
        let mut valid_sources = vec![0; 8];\
        for i in 0..std::cmp::min(sources.len(), 8) {\
            valid_sources[i] = 1; // Mark sources as valid up to our count\
        }\
        \
        // Create simplified input that matches circuit expectations\
        let input_json = json!({\
            "sourceCount": source_count,\
            "validSources": valid_sources\
        });\
        \
        Ok(input_json)\
    }' src/zk/multi_source_proof.rs

echo "Updated prepare_input_file function in multi_source_proof.rs"
echo "Try running the multi-source demo again with 'cargo run --bin multi_source_demo'"
