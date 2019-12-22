Notation used in formulas
=========================

.. list-table::
   :header-rows: 1
   :widths: auto

   * - This
     - Schoen-makers
     - Tang et al.
     - Description

   * - :math:`Z_q`
     - :math:`Z_q`
     - :math:`Z_q`
     - Additive group of integers modulo prime :math:`q`,
       used as the pre-image group for all group isomorphisms.

   * - :math:`Z_q^*`
     - :math:`Z_q^*`
     - :math:`Z_q^*`
     - :math:`Z_q \setminus \{0\}`

   * - :math:`G_q`
     - :math:`G_q`
     - :math:`G_q`
     - Finite cyclic group of prime order :math:`q`, used as the image group for all group isomorphisms.
       Computing discrete logarithms in this group must be infeasible.

   * - :math:`q`
     - :math:`q`
     - :math:`q`
     - Size of :math:`G_q` and :math:`Z_q`

   * - :math:`g_0`
     - :math:`g`
     - :math:`g`
     - Generator for :math:`G_q`

   * - :math:`g_1`
     -
     - :math:`h`
     - Generator for :math:`G_q`

   * - :math:`G_0`
     - :math:`G`
     - :math:`G`
     - Generator for :math:`G_q`

   * - :math:`G_1`
     -
     - :math:`H`
     - Generator for :math:`G_q`

   * - :math:`n`
     - :math:`n`
     - :math:`n`
     - Number of shareholders.

   * - :math:`x_i`
     - :math:`x_i`
     - :math:`x_i`
     - Private keys :math:`\in_R Z_q^*` for shareholders with :math:`1 \leq i \leq n`

   * - :math:`{y_i}_0`
     - :math:`y_i`
     - :math:`y_{i1}`
     - First public key part for shareholders, :math:`{y_i}_0 = G_0^{x_i}`

   * - :math:`{y_i}_1`
     -
     - :math:`y_{i2}`
     - Second public key part for shareholders, :math:`{y_i}_1 = G_1^{x_i}`

   * - :math:`x_r`
     -
     -
     - Private keys :math:`\in_R Z_q^*` for recipient

   * - :math:`{y_r}_0`
     -
     -
     - First public key part for recipient, :math:`{y_r}_0 = G_0^{x_r}`

   * - :math:`{y_r}_1`
     -
     -
     - Second public key part for recpient, :math:`{y_r}_1 = G_1^{x_r}`

   * - :math:`f_0(i)`
     - :math:`p(x)`
     - :math:`f(x)`
     - Polynomial with secret coefficients :math:`{α_j}_0`

   * - :math:`f_1(i)`
     -
     - :math:`g(x)`
     - Polynomial with secret coefficients :math:`{α_j}_1`

   * - :math:`α_{j_0}`
     - :math:`α_j`
     - :math:`α_j`
     - Secret coefficients for :math:`f_0`

   * - :math:`α_{j_1}`
     -
     - :math:`\beta_j`
     - Secret coefficients for :math:`f_1`

   * - :math:`i`
     - :math:`i`
     - :math:`i`
     - Unique index for shareholder, :math:`i \in [0,q)`, usually :math:`1 \leq i \leq n`.
