#!/usr/bin/env bash

set -e

# ECDHE-ECDSA-AES256-GCM-SHA384 (BearSSL)
openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout server-eckey.pem -out server-ecdsacert.pem
