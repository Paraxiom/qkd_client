#!/bin/bash

echo "🔍 Checking if HybridAuth is defined..."
grep -r "struct HybridAuth" src/

echo -e "\n🔍 Checking if authenticate() exists..."
grep -r "fn authenticate" src/quantum_auth/hybrid.rs

echo -e "\n🔍 Checking if HybridAuth is imported in enhanced_client.rs..."
grep -r "HybridAuth" src/bin/enhanced_client.rs

