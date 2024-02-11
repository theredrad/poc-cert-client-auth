#!/bin/bash

if ! command -v hey &> /dev/null; then
    echo "hey (http load generator) is not installed. please install hey to proceed."
    exit 1
fi

TOKEN_FILE="./credentials/$1/token"

if [ ! -f "$TOKEN_FILE" ]; then
  echo "Token file not found: $TOKEN_FILE"
  exit 1
fi

TOKEN=$(cat "$TOKEN_FILE")

# 10000 total requests, 100 concurrent
hey -n 10000 -c 100 -H "Authorization: Bearer $TOKEN" $2