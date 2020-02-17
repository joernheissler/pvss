.. _workflow.initialization:

Initialization
==============
Mathematical parameters must be chosen, such as a `cyclic group
<https://en.wikipedia.org/wiki/Cyclic_group>`_ and several generators for it.

In this implementation, the generators are determined deterministically by using a hash
function. This eliminates the need to communicate the generators. It is vital that nobody has
knowledge of the discrete logarith of any generator with regards to any other.  Hopefully the
below strategies meet the `Rigidity <https://safecurves.cr.yp.to/rigid.html>`_ property.

.. _workflow.initialization.rst255:

Ristretto255 group
------------------
The `Ristretto255 <https://ristretto.group/>`_ group is built upon `curve25519
<https://cr.yp.to/ecdh.html>`_.  Basically this eliminates the cofactor from curve25519,
ensuring that all group elements are unique and generate the complete group. The group and its
operations are designed to be used for zero-knowledge protocols such as PVSS.

`Libsodium <https://download.libsodium.org/doc/advanced/point-arithmetic/ristretto>`_ is used to
carry out the various mathematical operations.

Generators are determined by computing HMAC-SHA2-512 over the DER encoding of the :ref:`system
parameters <asn1.examples.rst255.systemparameters>` and the LaTeX notation of the generator name
is used as the hmac key, i.e. ``"G_0", "G_1", "g_0", "g_1"``.  The mac is passed through the
``point_from_hash`` function to determine the generator points.

The generators are:

* :math:`G_0`: ``3cc42cdf5ffc59a96093c572e6429ce8c621695d8f99156819701070c9895b02``
* :math:`G_1`: ``76e9d24f586f4878f24d11069e1ab0420f20793f73d79d2a7b753c522ce8c468``
* :math:`g_0`: ``90199c1a0446a5bb8fb88de3266e27b74565b14c74de153f8054302434040a7b``
* :math:`g_1`: ``0cd425c734d93957091c5871eb2c1f8dd222c56310c4df58117bce9bf212d820``

.. _workflow.initialization.qr:

Quadratic Residue Group
-----------------------
The `Multiplicative group <https://en.wikipedia.org/wiki/Multiplicative_group>`_ of `quadratic
residues <https://en.wikipedia.org/wiki/Quadratic_residue>`_ modulo `safe prime
<https://en.wikipedia.org/wiki/Safe_prime>`_ :math:`p = 2q+1` is commonly used for cryptographic
operations, e.g. Diffie Hellmann. Useful property of quadratic residues are that they always
generate the complete group, are easy to find (square any number) and it's easy to determine if
a given number is a quadratic residue with the `Legendre symbol
<https://en.wikipedia.org/wiki/Legendre_symbol>`_.  The implementation uses `gmpy2
<https://pypi.org/project/gmpy2/>`_ to provide faster operations. Still, this group is very slow
when compared to Ristretto255 and the message sizes are a lot bigger.

To determine generators, HMAC-SHA2-256 is repeatedly computed and the results concatenated until
at least twice the bit size of the prime :math:`p` is reached.  The LaTeX notation of the
generator name is used as the key for the MAC operation. The input to the MAC is the previous
MAC. As initial value, the DER representation of the :ref:`system parameters
<asn1.examples.qr.systemparameters>` is used. Finally, the concatenated MACs are interpreted as
an integer and squared to get a quadratic residue, i.e.  a generator for the group. The system
parameters depend on the prime :math:`p`, so there will be different generators for each prime. 
