Notation used in formulas
=========================

==============  ==============  ==============  ========================================================
Present         Schoen-         Tang et al.     Description
                makers
==============  ==============  ==============  ========================================================
:math:`Z_q`     :math:`Z_q`     :math:`Z_q`     Additive group of integers modulo prime :math:`q`, used
                                                as the pre-image group for all group isomorphisms.
:math:`Z_q^*`   :math:`Z_q^*`   :math:`Z_q^*`   :math:`Z_q \setminus \{0\}`
:math:`G_q`     :math:`G_q`     :math:`G_q`     Finite cyclic group of prime order :math:`q`, used as
                                                the image group for all group isomorphisms. Computing
                                                discrete logarithms in this group must be infeasible.
:math:`q`       :math:`q`       :math:`q`       Size of :math:`G_q` and :math:`Z_q`
:math:`g_0`     :math:`g`       :math:`g`       Generator for :math:`G_q`
:math:`g_1`                     :math:`h`       Generator for :math:`G_q`
:math:`G_0`     :math:`G`       :math:`G`       Generator for :math:`G_q`
:math:`G_1`                     :math:`H`       Generator for :math:`G_q`
:math:`n`       :math:`n`       :math:`n`       Number of shareholders.
:math:`x_i`     :math:`x_i`     :math:`x_i`     Private keys :math:`\in_R Z_q^*` for shareholders with
                                                :math:`1 \leq i \leq n`
:math:`y_i_0`   :math:`y_i`     :math:`y_{i1}`  First public key part for shareholders,
                                                :math:`y_i_0 = G_0^{x_i}`
:math:`y_i_1`                   :math:`y_{i2}`  Second public key part for shareholders,
                                                :math:`y_i_1 = G_1^{x_i}`
:math:`x_r`                                     Private keys :math:`\in_R Z_q^*` for recipient
:math:`y_r_0`                                   First public key part for recipient,
                                                :math:`y_r_0 = G_0^{x_r}`
:math:`y_r_1`                                   Second public key part for recpient,
                                                :math:`y_r_1 = G_1^{x_r}`
:math:`f_0(i)`  :math:`p(x)`    :math:`f(x)`    Polynomial with secret coefficients :math:`\alpha_j_0`
:math:`f_1(i)`                  :math:`g(x)`    Polynomial with secret coefficients :math:`\alpha_j_1`
:math:`         Moep
\alpha_j_0`
==============  ==============  ==============  ========================================================
