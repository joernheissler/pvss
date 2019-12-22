Operations
==========

The protocol consists of six steps which are executed in sequence.
The last three steps can be repeated if another reconstruction is desired.

Each step requires the public input from the previous steps.

Recipients of public values must check if those values conform to this protocol, e.g.
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
Typically those are :math:`1 \leq i \leq n`. Each shareholder generates a private key
:math:`x_i \in Z_q^*` and the corresponding public key
:math:`{y_i}_0 = G_0^{x_i}`, :math:`{y_i}_1 = G_1^{x_i}`.

The private key is kept private and the public key is made public.

Secret sharing
--------------
The dealer carries out a number of steps:

* Define how many shares are required to reconstruct the secret: :math:`t \in [1,n]`.
  This is also known as the size of the *qualified subset*.
* Choose two random polynomials :math:`f_0(i) = \sum\limits_{j=0}^{t-1} {\alpha_{j}}_0 i^j` and
  :math:`f_1(i) = \sum\limits_{j=0}^{t-1} {\alpha_{j}}_1 i^j` with coefficients
  :math:`{\alpha_{j}}_{0,1} \in_R Z_q` for :math:`j \in [0,t)`.
* Compute the shared secret: :math:`S = G_0^{{\alpha_0}_0} G_1^{{\alpha_0}_1}`.
* Compute commitments for the coefficients:
  :math:`C_j = g_0^{{\alpha_j}_0} g_1^{{\alpha_j}_1}` for :math:`j \in [0,t)`.
* For each shareholder :math:`i`, compute:

  * Random values :math:`{k_i}_0 \in_R Z_q` and :math:`{k_i}_1 \in_R Z_q`
  * Encrypted share of the secret: :math:`Y_i = {y_i}_0^{f_0(i)} {y_i}_1^{f_1(i)}`
  * Commitment for random share: :math:`Y'_i = {y_i}_0^{{k_i}_0} {y_i}_1^{{k_i}_1}`
  * :math:`X_i = g_0^{f_0(i)} g_1^{f_1(i)}`
  * :math:`X'_i = g_0^{{k_i}_0} g_1^{{k_i}_1}`

* Compute the challenge using a cryptographic hash function
  :math:`c = H(G, g_0, g_1, G_0, G_1,  C_j, y_i, Y_i, Y'_i, X_i, X'_i)`.
  The output of the hash function needs to be a non-negative integer. This can be
  achieved e.g. by using ``sha2_256`` and treating the 256 bit output as an integer.

* Compute the response: :math:`{s_i}_0 = {k_i}_0 + c f_0(i)` and
  :math:`{s_i}_1 = {k_i}_1 + c f_1(i)` for each shareholder :math:`i`.

The dealer then makes the values :math:`Y_i, {s_i}_{0,1}, C_j, c` public.

The shared secret :math:`S` can be used to encrypt some payload, e.g.
by computing a hash over it and using it as the key for AES-GCM.
It must then be discarded.

The polynomials :math:`f_{0,1}(i)` and the random values :math:`{k_i}_{0,1}`
are secret and must be discarded.

The values :math:`X'_i, Y'_i` could be made public, but other parties can recompute them.
So they are simply discarded.


Recipient key pair generation
-----------------------------
The recipient generates a private key :math:`x_r \in Z_q^*` and the corresponding public key
:math:`{y_r}_0 = G_0^{x_r}`, :math:`{y_r}_1 = G_1^{x_r}`.

The private key is kept private and the public key is made public.

If the following two operations are executed quickly, the private key should be
kept in ephemeral storage to reduce the risk of subsequential leakage.

Share reencryption
------------------
At least :math:`t` shareholders need to decrypt their share and use Elgamal Encryption to
reencrypt it with the recipient's public key:

* Decrypt share: :math:`s_i = Y_i^{\frac{1}{x_i}}`
* :math:`a_0, a_1 \in_R Z_q`
* :math:`c_1 = G_0^{a_0} G_1^{a_1}`
* :math:`c_2 = s_i {y_r}_0^{a_0} {y_r}_1^{a_1}`
* :math:`v_0 = -a_0x_i,~ v_1 = -a_1x_i`
* :math:`k_{a_0,a_1,v_0,v_1,x} \in_R Z_q`
* :math:`r_y = c_2^{k_x} {y_r}_0^{k_{v_0}} {y_r}_1^{k_{v_1}}`
* :math:`r_u = (G_0G_1)^{k_x}`
* :math:`r_{c_1} = G_0^{k_{a_0}} G_1^{k_{a_1}}`
* :math:`r_1 = c_1^{k_x} G_0^{k_{v_0} G_1^{k_{v_1}}}`
* :math:`c = H(G, g_0, g_1, G_0, G_1,  C_j, y_i, Y_i, {s_i}_{0,1}, c, r_y, r_u, r_{c_1}, r_1)`
* :math:`s_x = k_x + c x_i`
* :math:`{s_a}_0 = {k_a}_0 + c a_0`
* :math:`{s_a}_1 = {k_a}_1 + c a_1`
* :math:`{s_v}_0 = {k_v}_0 + c v_0`
* :math:`{s_v}_1 = {k_v}_1 + c v_1`

Secret reconstruction
---------------------

