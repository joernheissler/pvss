##############################################
Publicly Verifiable Secret Splitting in python
##############################################

This project is a python (>= 3.7) implementation (library and CLI) of
`Publicly Verifiable Secret Splitting (PVSS)
<https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing>`_.
PVSS is a non-interactive cryptographic protocol between multiple participants
for splitting a random secret into multiple shares and distributing them amongst a
group of users.  An arbitrary subset of those users (e.g. any 3 out of 5) can
later cooperate to reassemble the secret.

The common use case for secret splitting is to create a highly durable backup of
highly sensitive data such as cryptographic keys.

All communication between the participants is public and everyone can verify
that all messages have been correctly created according to the protocol. This
verification is done through `non-interactive zero-knowledge proofs
<https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof>`_.

The math is based upon the paper `Non-Interactive and Information-Theoretic
Secure Publicly Verifiable Secret Sharing <https://eprint.iacr.org/2004/201.ps>`_
by *Chunming Tang* et al.

One notable difference to their paper is the addition of a receiver user:
In their scheme the secret is made public while it is being reassembled, which
violates the goal to keep the secret secret. To address this issue, the users no longer
disclose their share of the secret but use `ElGamal encryption
<https://en.wikipedia.org/wiki/ElGamal_encryption>`_ to securely convey the share to a
separate receiver user who will then reassemble the secret. Like all other communication,
the encrypted share is public and it can be verified that the users followed the protocol.

************
Installation
************

Requirements
============

* python (>= 3.7)
* At least one of:
    + `libsodium <https://libsodium.org/>`_ (recommended, for `Ristretto255 <https://ristretto.group/>`_ group)
    + `gmpy2 <https://pypi.org/project/gmpy2/>`_ (Group of quadratic residues modulo a large safe prime)


Using `pip`
===========

* Create a virtualenv
* ``pip install pvss``  (and optionally ``gmpy2``)

Using `poetry`
==============

* ``poetry install``


*******
Example
*******

The following sequence of shell commands is executed by six different users who
share a data directory. E.g. use git to synchronize it between the users. All
files inside ``datadir`` are public. All files outside of it are private.
::

    (init)     $ pvss datadir genparams rst255 
    (alice)    $ pvss datadir genuser Alice alice.key 
    (boris)    $ pvss datadir genuser Boris boris.key 
    (chris)    $ pvss datadir genuser Chris chris.key 
    (dealer)   $ pvss datadir splitsecret 2 secret0.der 
    (receiver) $ pvss datadir genreceiver recv.key 
    (boris)    $ pvss datadir reencrypt boris.key 
    (alice)    $ pvss datadir reencrypt alice.key 
    (receiver) $ pvss datadir reconstruct recv.key secret1.der 

``secret0.der`` and ``secret1.der`` should compare equal.
The *dealer* and *receiver* can encrypt an actual payload by using that file as a shared key.
