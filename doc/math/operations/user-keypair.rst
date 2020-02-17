.. _math.operations.userkey:

Key Pair generation
-------------------

There are :math:`n` users. Each is assigned a unique integer :math:`i \in [1, q)`.
Typically those are :math:`1 \leq i \leq n`. Each user generates a private key
:math:`x_i \in Z_q^*` and the corresponding public key
:math:`{y_i}_0 = G_0^{x_i}`, :math:`{y_i}_1 = G_1^{x_i}`.

The private key is kept private and the public key is published.
