.. _math.operations.reconstruction:

Secret reconstruction
=====================

When at least :math:`t` users re-encrypted their shares with the receiver's public key,
the receiver can reconstruct the secret:

* | Decrypt each re-encrypted share:
  | :math:`S_i = b_i \cdot a_i^{\frac{1}{x_r}}`
* | Reconstruct the secret:
  | :math:`S = \prod\limits_i S_i^{\lambda_i},~ \lambda_i = \prod\limits_{i', i' \ne i} \frac{i'}{i' - i}`
  | where :math:`i, i'` are the user indices for all re-encrypted shares.
