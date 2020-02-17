.. _math.operations.receiverkey:

Receiver key pair generation
----------------------------
The recipient generates a private key :math:`x_r \in Z_q^*` and the corresponding public key
:math:`{y_r}_0 = G_0^{x_r}`, :math:`{y_r}_1 = G_1^{x_r}`.

The private key is kept private and the public key is published.

If the following two operations are executed quickly, the private key should be
kept in ephemeral storage to reduce the risk of subsequential leakage.
