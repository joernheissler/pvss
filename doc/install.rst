Installation
============
``PVSS``'s dependencies are:

* python (>= 3.7)
* At least one of:
    + `libsodium <https://libsodium.org/>`_ (>= 1.0.18, recommended, for `Ristretto255 <https://ristretto.group/>`_ group)

      On Debian (Bullseye / 11 and later) or Ubuntu (Eoan / 19.10 and later):

      .. code-block:: console

          # apt install libsodium23

    + `gmpy2 <https://pypi.org/project/gmpy2/>`_ (Group of quadratic residues modulo a large safe prime)

You can install ``PVSS`` with ``pip``:

.. code-block:: console

    $ pip install pvss

And optionally:

.. code-block:: console

    $ pip install gmpy2
