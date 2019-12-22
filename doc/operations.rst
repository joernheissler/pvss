Operations
==========

The protocol consists of six steps which are executed in sequence.
The last three steps can be repeated if another reconstruction is desired.

Each step requires the public input from the previous steps.

Recipients of public values must check if those values conforman to this protocol, e.g.
if groups are really of prime order and if group members really are inside the group.

Recipients of public values must also ensure that those value were not modified by a third party.
How to accomplish this is out of scope of this chapter.

Initialization
--------------

Choose a prime order group :math:`G_q` and four distinct generators :math:`g_0,g_1,G_0,G_1` for it.

No party must know the discrete logarithm of any generator with respect to any other. Therefore those
generators must be picked from :math:`G_q` using a public procedure which follows the concept of
`nothing-up-my-sleeve <https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number>`_.

The chosen group and generators are public.

**Example groups to choose from:**

  - `Ristretto255 <https://ristretto.group/>`_, a group built upon `curve25519 <https://cr.yp.to/ecdh.html>`_.

  - `Multiplicative group <https://en.wikipedia.org/wiki/Multiplicative_group>`_ of
    `quadratic residues <https://en.wikipedia.org/wiki/Quadratic_residue>`_ modulo
    `safe prime <https://en.wikipedia.org/wiki/Safe_prime>`_ :math:`p = 2q+1`

  - `NIST P-256 <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>`_ (§ D.1.2.3).
    Should only be used if required by hardware constraints.

Shareholder key pair generation
-------------------------------
There are :math:`n` shareholders. Each is assigned a unique integer :math:`i \in [1, q)`.
Typically those are :math:`1 \leq i \leq n`. Each shareholder generates a private key :math:`x_i`
and the corresponding public key :math:`y_i_0 = G_0^{x_i}`, :math:`y_i_1 = G_1^{x_i}`.

The private key is kept private and the public key is made public.

Secret sharing
--------------
The dealer 

Recipient key pair generation
-----------------------------
The recipient generates a private key :math:`x_r` and the corresponding public key
:math:`y_r_0 = G_0^{x_r}`, :math:`y_r_1 = G_1^{x_r}`.

The private key is kept private and the public key is made public.

If the following two operations are executed quickly, the private key should be
kept in ephemeral storage to reduce the risk of subsequential leakage.

Share reencryption
------------------


Secret reconstruction
---------------------

