#!/bin/bash
# compare_cert_password.sh
echo "Comparing certificate password usage between reporter client and ETSI API..."

echo -e "\nReporter client (src/reporter/qkd_client.rs):"
grep -R "from_pkcs12_der" src/reporter/qkd_client.rs

echo -e "\nETSI API (src/qkd/etsi_api.rs):"
grep -R "from_pkcs12_der" src/qkd/etsi_api.rs

echo -e "\nDiff between the two:"
diff <(grep -R "from_pkcs12_der" src/reporter/qkd_client.rs) <(grep -R "from_pkcs12_der" src/qkd/etsi_api.rs)

