.. _workflow.splitting:

Secret splitting
================
The *dealer* randomly generates a secret, computes a share for each user and encrypts each share
with the corresponding user's public key.  The generated secret is used to encrypt the actual
payload. The encrypted payload and the encrypted shares are published.
