#!/bin/bash

# URLs and certificate paths
ENCRYPT_KEY_URL="https://192.168.0.4/api/v1/keys/bobsae/enc_keys"
DECRYPT_KEY_URL="https://192.168.0.2/api/v1/keys/alicesae/dec_keys"

CACERT_PATH="toshiba-ca.cert.pem"
ALICE_KEY_PATH="toshiba-entity.key.pem"
ALICE_CERT_PATH="toshiba-entity-alice-client.cert.pem"

BOB_KEY_PATH="toshiba-entity.key.pem"
BOB_CERT_PATH="toshiba-entity-bob-client.cert.pem"

# Fetch encrypted key
echo "Fetching encrypted key..."
ENCRYPT_RESPONSE=$(curl -s --cacert "$CACERT_PATH" --key "$ALICE_KEY_PATH" --cert "$ALICE_CERT_PATH" $ENCRYPT_KEY_URL)

# Extract key_ID from the response
KEY_ID=$(echo $ENCRYPT_RESPONSE | jq -r '.keys[0].key_ID')

if [ -z "$KEY_ID" ]; then
    echo "Failed to extract key_ID from encryption response."
    exit 1
fi

echo "Extracted key_ID: $KEY_ID"

# Fetch decrypted key using extracted key_ID
echo "Fetching decrypted key..."
DECRYPT_RESPONSE=$(curl -s --cacert "$CACERT_PATH" --key "$BOB_KEY_PATH" --cert "$BOB_CERT_PATH" "${DECRYPT_KEY_URL}?key_ID=${KEY_ID}")

if [ $? -ne 0 ]; then
    echo "Failed to fetch decrypted key."
    exit 1
fi

echo "Decrypted Key Response: $DECRYPT_RESPONSE"
