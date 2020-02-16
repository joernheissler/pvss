Protocol Workflow
=================
The PVSS protocol consists of multiple steps. Each step yields one or multiple messsages that
need to be available to the next steps.

Initialization
--------------------
Mathematical parameters must be chosen, such as a `cyclic group
<https://en.wikipedia.org/wiki/Cyclic_group>`_ and several generators for it.

User key pair generation
-------------------------------
Each user generates a private key (which is never disclosed to any other party), computes the
public key and shares it.

Secret splitting
----------------
The *dealer* randomly generates a secret, computes a share for each user and encrypts each share
with the corresponding user's public key.  The generated secret is used to encrypt the actual
payload. The encrypted payload and the encrypted shares are published.

Recipient key pair generation
-----------------------------
As soon as there is need to reassemble the secret, the intended recipient of the secret
generates another keypair and shares the public key.

Share re-encryption
-------------------
Some of the users decrypt their share and re-encrypt it with the recipient's public key.

Secret reassembly
-----------------
The recipient decrypts those shares and reassembles the secret.
