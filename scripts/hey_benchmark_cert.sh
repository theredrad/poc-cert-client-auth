#!/bin/bash

if ! command -v hey &> /dev/null; then
    echo "hey (http load generator) is not installed. please install hey to proceed."
    exit 1
fi

CERT_FILE="./credentials/$1/certificate.crt"

if [ ! -f "$CERT_FILE" ]; then
  echo "certificate file not found: $CERT_FILE"
  exit 1
fi

CERT_BASE64=$(base64 < "$CERT_FILE")

PRIVATE_KEY_FILE="./credentials/$1/private.key"

if [ ! -f "$PRIVATE_KEY_FILE" ]; then
  echo "private key file not found: $PRIVATE_KEY_FILE"
  exit 1
fi

PRIVATE_KEY=$(cat "$PRIVATE_KEY_FILE")

REQUEST_URI=$2
REUQUEST_BODY_MD5=""
TIMESTAMP=$(date -u +%s)
NONCE=$RANDOM

# use newline instead of \n to avoid character escape
SIGNATURE_BODY="GET
${REQUEST_URI}
${REUQUEST_BODY_MD5}
${TIMESTAMP}
${NONCE}"

SIGNATURE=$(echo -n "$SIGNATURE_BODY" | openssl sha256 -binary | openssl pkeyutl -sign -inkey $PRIVATE_KEY_FILE -keyform DER -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64)

# 10000 total requests, 100 concurrent
hey -n 10000 -c 100 -H "X-Client-Cert: $CERT_BASE64" -H "X-Timestamp: $TIMESTAMP" -H "X-Signature: $SIGNATURE" -H "X-Nonce: $NONCE" $2
