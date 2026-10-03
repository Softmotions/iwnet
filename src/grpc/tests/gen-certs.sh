#!/usr/bin/env bash

set -e

# ECDHE-ECDSA-AES256-GCM-SHA384 (BearSSL)
openssl ecparam -name prime256v1 -genkey -noout -out grpc-server-key.pem
openssl req -x509 -new -key grpc-server-key.pem -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -out grpc-server-cert.pem
