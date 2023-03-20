.. _math.operations.reencryption:

Share reencryption
------------------
A user can decrypt their share and use ElGamal Encryption to re-encrypt it with the receiver's public key.
The user needs to produce a non-interactive zero knowledge proof to show that the reencrypted secret was correctly
computed.

* | Decrypt share by raising it to power of the multiplicative inverse of the user's private key:
  | :math:`S_i = Y_i^{\frac{1}{x_i}}`

* | Choose two random values:
  | :math:`w_0, w_1 \in_R Z_q`

* | Re-encrypt decrypted share using ElGamal encryption:
  | :math:`a_i = G_0^{w_0} \cdot G_1^{w_1}`
  | :math:`b_i = S_i \cdot {y_r}_0^{w_0} \cdot {y_r}_1^{w_1}`

Next, the user needs to prove knowledge of the secret values :math:`x_i, S_i, w_0, w_1` such that

* :math:`y_i = {y_i}_0 \cdot {y_i}_1 = (G_0 \cdot G_1)^{x_i}`
* :math:`Y_i = S_i^{x_i}`
* :math:`a_i = G_0^{w_0} \cdot G_1^{w_1}`
* :math:`b_i = S_i \cdot {y_r}_0^{w_0} \cdot {y_r}_1^{w_1}`

hold. This can't be proven directly because :math:`S_i` is secret.

* | Compute two helper variables:
  | :math:`v_0 = -w_0x_i,~ v_1 = -w_1x_i`
* | Eliminate :math:`S_i`:
  | :math:`Y_i = b_i^{x_i} \cdot {y_r}_0^{v_0} \cdot {y_r}_1^{v_1}`
* | The user then needs to prove
  | :math:`v_0 = -w_0x_i \wedge v_1 = -w_0x_i`
  | which can't be done directly either.
* | Instead, the user proves
  | :math:`e = a_i^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1}`
  | where :math:`e` is the identity element of the image group.

The user thus proves knowledge of the secret values :math:`x_i, v_0, v_1, w_0, w_1` such that

* :math:`y_i = (G_0 \cdot G_1)^{x_i}`
* :math:`a_i = G_0^{w_0} \cdot G_1^{w_1}`
* :math:`Y_i = b_i^{x_i} \cdot {y_r}_0^{v_0} \cdot {y_r}_1^{v_1}`
* :math:`e = a_i^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1}`

hold. Compute:

* | Choose random values :math:`k_{x,v_0,v_1,w_0,w_1} \in_R Z_q`
* | Random commitment for :math:`y_i`.
  | :math:`y'_i = (G_0 \cdot G_1)^{k_x}`
* | Random commitment for :math:`Y_i`.
  | :math:`Y'_i = b_i^{k_x} \cdot {y_r}_0^{k_{v_0}} \cdot {y_r}_1^{k_{v_1}}`
* | Random commitment for :math:`a_i`.
  | :math:`a_i' = G_0^{k_{w_0}} \cdot G_1^{k_{w_1}}`
* | Random commitment for :math:`e`.
  | :math:`e' = a_i^{k_x} \cdot G_0^{k_{v_0}} \cdot G_1^{k_{v_1}}`

Compute the challenge for the zero knowledge proof using a cryptographic hash function
:math:`c = H(G_q, g_0, g_1, G_0, G_1, XXX, {y_r}_0, {y_r}_1, y'_i, Y'_i, a'_i, e')`

Compute the response for the zero knowledge proof:

* :math:`s_x     = k_x     + c x_i`
* :math:`{s_v}_0 = {k_v}_0 + c v_0`
* :math:`{s_v}_1 = {k_v}_1 + c v_1`
* :math:`{s_w}_0 = {k_w}_0 + c w_0`
* :math:`{s_w}_1 = {k_w}_1 + c w_1`

The user publishes the values :math:`a_i, b_i, c, s_x, {s_v}_0, {s_v}_1, {s_w}_0, {s_w}_1`.

Verification
~~~~~~~~~~~~
To verify that the re-encrypted share was computed correctly, the following steps are carried
out:

* :math:`y'_i = (G_0 \cdot G_1)^{s_x} \cdot ({y_i}_0 \cdot {y_i}_1)^{-c}`
* :math:`Y'_i = b_i^{s_x} \cdot {y_r}_0^{s_{v_0}} \cdot {y_r}_1^{s_{v_1}} \cdot Y_i^{-c}`
* :math:`a'_i = G_0^{s_{w_0}} \cdot G_1^{s_{w_1}} \cdot a_i^{-c}`
* :math:`e'   = a_i^{s_x} \cdot G_0^{s_{v_0}} \cdot G_1^{s_{v_1}}`
* :math:`c' = H(G_q, g_0, g_1, G_0, G_1, XXX, {y_r}_0, {y_r}_1, y'_i, Y'_i, a'_i, e')`
* Verify that :math:`c = c'`

Completeness
~~~~~~~~~~~~
An honest prover can always carry out the operations described above to convince any verifier.

Soundness
~~~~~~~~~
Assuming a random oracle model, the hash function might return the value :math:`c_0` and in a different universe
it might return :math:`c_1` for the same input, where :math:`c_1 = c_0 + 1`. If the prover is somehow able to generate
valid :math:`{s_{x_i}}_0` and :math:`{s_{x_i}}_1` with high probability, he can e.g. compute
:math:`{s_{x_i}}_1 - {s_{x_i}}_0 = (k_{x_i} + (c_0 + 1) x_i) - (k_{x_i} + c_0 x_i) = x_i`.
The same idea is applied to the other secret variables. I.e. even if a "lucky" prover does not know the secret
variables, he could easily compute them. We don't believe in such luck but assume that the prover knows the secrets.

This proves knowledge of values :math:`x_i, v_0, v_1, w_0, w_1` such that:

 * :math:`y_i = (G_0 \cdot G_1)^{x_i}`
 * :math:`a_i = G_0^{w_0} \cdot G_1^{w_1}`
 * :math:`Y_i = b_i^{x_i} \cdot {y_r}_0^{v_0} \cdot {y_r}_1^{v_1}`

To prove that :math:`e = a_i^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1}`, remember that the verifier computes :math:`e'`
and includes it in the hash input.

:math:`e' = a_i^{s_{x_1}} \cdot G_0^{s_{v_0}} \cdot G_1^{s_{v_1}}
= a_i^{k_{x_i} + cx_i} \cdot G_0^{k_{v_0} + cv_0} \cdot G_1^{k_{v_1} + cv_1}
= (a_i^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1})^c \cdot (a_i^{k_{x_i}} \cdot G_0^{k_{v_0}} \cdot G_1^{k_{v_1}})`

If :math:`e = a_i^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1}` holds, the prover can easily compute :math:`e' = a_i^{k_{x_i}} \cdot G_0^{k_{v_0}} \cdot G_1^{k_{v_1}}` which does not depend on :math:`c`. Otherwise, the value of :math:`e'` would depend on :math:`c` and vice versa. It may be possible to find such a pair, but it's infeasible. So we assume that it does hold.

Next, substitute :math:`a_i`:
:math:`e = (G_0^{w_0} \cdot G_1^{w_1})^{x_i} \cdot G_0^{v_0} \cdot G_1^{v_1}
= G_0^{w_0x_i + v_0} \cdot G_1^{w_0x_i + v_1}`.

The prover does not know the discrete logarithm of :math:`G_0` with regards to :math:`G_1` or vice versa,
so we can assume that the prover chose :math:`v_0 = -w_0x_i \wedge v_1 = -w_1x_i`.

It follows that :math:`Y_i^{\frac{1}{x_i}} = b_i \cdot {y_r}_0^{-w_0} \cdot {y_r}_1^{-w_1} = S_i`.

Zero Knowledge
~~~~~~~~~~~~~~
The response values :math:`s_…` each depend on a different random number :math:`k_…` and are
evenly distributed over all possible values.  A verifier could generate random responses which
obviously would contain no useful information at all. There is no way to distinguish an actual
response from a random response.

The challenge :math:`c` which is provided by the prover is also computed by the verifier,
so it doesn't depend on secret information either.

If a verifier can compute the discrete logarithm for any of the random commitments, they could
deduce the secret value. But this is just as hard as computing the secret value directly.
