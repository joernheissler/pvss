.. _index:

Publicly Verifiable Secret Splitting in python
==============================================
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
by *Chunming Tang* et al. who extended *Berry Schoenmaker*'s paper
`A Simple Publicly Verifiable Secret Sharing Scheme and its Application to Electronic Voting
<https://www.win.tue.nl/~berry/papers/crypto99.pdf>`_ which in turn is based on
`Shamir's Secret Sharing <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing>`_.

One notable difference to prior work is the addition of a receiver user:
In their scheme the secret is made public while it is being reassembled, which
violates the goal to keep the secret secret. To address this issue, the users no longer
disclose their share of the secret but use `ElGamal encryption
<https://en.wikipedia.org/wiki/ElGamal_encryption>`_ to securely convey the share to a
separate receiver user who will then reassemble the secret. Like all other communication,
the encrypted share is public and it can be verified that the users followed the protocol.

.. _index.toc:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install
   usecases
   workflow/index
   cli
   api
   math/index
   ASN1
   security
   glossary
   contributing
   changelog
   license


Indices and tables
------------------
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
