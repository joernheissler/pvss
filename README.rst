############################################
Publicly Verifiable Secret Sharing in python
############################################

Introduction
============

`Publicly Verifiable Secret Sharing
<https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing>`_
is a cryptographic protocol for splitting a secret into multiple shares
and distributing them amongst a group of shareholders.
A subset of the shareholders (e.g. any 3 out of 5) can later reassemble the
secret.

All communication between the participants is public and everyone can verify
that all messages have been correctly created according to the protocol.



This project is based upon the paper "Non-Interactive and Information-Theoretic
Secure Publicly Verifiable Secret Sharing" by *Chunming Tang* et al. [TANG2004]_

In the original paper the secret is made public while it is being reconstructed.

`ElGamal encryption <https://en.wikipedia.org/wiki/ElGamal_encryption>`
`Non-interactive zero-knowledge proofs <https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof>`.


.. [TANG2004] https://eprint.iacr.org/2004/201.ps


Operations
==========
The protocol consists of multiple steps. Each step yields one or multiple
messsages that need to be available to the next steps.

Initialization
--------------------
Mathematical parameters must be chosen, such as a `cyclic group
<https://en.wikipedia.org/wiki/Cyclic_group>` and several
generators for it.

Safekeeper key pair generation
------------------------------
Each shareholder generates a private key (which is never disclosed to
any other party), computes the public key and shares it.

Secret sharing
--------------
The "dealer" randomly generates a secret, computes a share for each
shareholder and encrypts each share with the corresponding shareholder's public
key.
The generated secret is used to encrypt the actual payload. The encrypted payload
and the encrypted shares are published.

Recipient key pair generation
-----------------------------
As soon as there is need to reassemble the secret, the intended recipient of
the secret generates another keypair and shares the public key.

Share re-encryption
-------------------
Some of the shareholders decrypt their share and re-encrypt it with the
recipient's public key.

Secret reassembly
-----------------
The recipient decrypts those shares and reconstructs the secret.


.. XXX
   asn.1
   available groups
   sharing real secrets (encrypt with AES-GCM)
   don't store pubkeys in shares, only the username


Security
========
