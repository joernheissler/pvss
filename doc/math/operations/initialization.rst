.. _math.operations.initialization:

Initialization
--------------

Choose a prime order group :math:`G_q` in which computing discrete logarithms is infeasible.
Also choose four distinct generators :math:`g_0,g_1,G_0,G_1` for it.

No party must know the discrete logarithm of any generator with respect to any other. Therefore those
generators must be picked from :math:`G_q` using a public procedure which follows the concept of
`nothing-up-my-sleeve <https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number>`_, e.g. by appying
a cryptographic hash function to sensible input values.

The chosen group and generators are public.

**Example groups to choose from:**

  - `Ristretto255 <https://ristretto.group/>`_, a group built upon `curve25519 <https://cr.yp.to/ecdh.html>`_.

  - `Multiplicative group <https://en.wikipedia.org/wiki/Multiplicative_group>`_ of
    `quadratic residues <https://en.wikipedia.org/wiki/Quadratic_residue>`_ modulo
    `safe prime <https://en.wikipedia.org/wiki/Safe_prime>`_ :math:`p = 2q+1`

  - `NIST P-256 <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>`_ (§ D.1.2.3).
    Should only be used if required by hardware constraints.
