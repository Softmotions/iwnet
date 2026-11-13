# Pending

New records are on the top.

## s2n-tls backend

- The s2n-tls adapter creates a `s2n_config` and parses the certificate
  chain/private key for every accepted connection (same as the BearSSL adapter does).
  Sharing a single config per server would avoid this cost.
