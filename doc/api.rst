.. _lib:

Library Usage
=============
The public API is accessible through the :class:`Pvss` class. Each instance stores the public
state of a complete ``PVSS`` :ref:`workflow <workflow>`. Messages created in one instance must be transferred
somehow (network, git repo, etc.) and be imported into the other instances.

.. _lib.example:

Example
-------

The following code is equivalent to the :ref:`CLI example <cli.example>`, if it would be ran
inside a single python process:

.. code-block:: python

    from pvss import Pvss
    from pvss.ristretto_255 import create_ristretto_255_parameters

    # init, genparams
    pvss_init = Pvss()
    params = create_ristretto_255_parameters(pvss_init)

    # alice, genuser
    pvss_alice = Pvss()
    pvss_alice.set_params(params)
    alice_priv, alice_pub = pvss_alice.create_user_keypair("Alice")

    # boris, genuser
    pvss_boris = Pvss()
    pvss_boris.set_params(params)
    boris_priv, boris_pub = pvss_boris.create_user_keypair("Boris")

    # chris, genuser
    pvss_chris = Pvss()
    pvss_chris.set_params(params)
    chris_priv, chris_pub = pvss_chris.create_user_keypair("Chris")

    # dealer, splitsecret
    pvss_dealer = Pvss()
    pvss_dealer.set_params(params)
    pvss_dealer.add_user_public_key(chris_pub)
    pvss_dealer.add_user_public_key(alice_pub)
    pvss_dealer.add_user_public_key(boris_pub)
    secret0, shares = pvss_dealer.share_secret(2)

    # receiver, genreceiver
    pvss_receiver = Pvss()
    pvss_receiver.set_params(params)
    recv_priv, recv_pub = pvss_receiver.create_receiver_keypair("receiver")

    # boris, reencrypt
    pvss_boris.add_user_public_key(alice_pub)
    pvss_boris.add_user_public_key(chris_pub)
    pvss_boris.set_shares(shares)
    pvss_boris.set_receiver_public_key(recv_pub)
    reenc_boris = pvss_boris.reencrypt_share(boris_priv)

    # alice, reencrypt
    pvss_alice.add_user_public_key(boris_pub)
    pvss_alice.add_user_public_key(chris_pub)
    pvss_alice.set_shares(shares)
    pvss_alice.set_receiver_public_key(recv_pub)
    reenc_alice = pvss_alice.reencrypt_share(alice_priv)

    # receiver, reconstruct
    pvss_receiver.add_user_public_key(boris_pub)
    pvss_receiver.add_user_public_key(chris_pub)
    pvss_receiver.add_user_public_key(alice_pub)
    pvss_receiver.set_shares(shares)
    pvss_receiver.add_reencrypted_share(reenc_alice)
    pvss_receiver.add_reencrypted_share(reenc_boris)
    secret1 = pvss_receiver.reconstruct_secret(recv_priv)

    print(secret0 == secret1)

.. _lib.reference:

API reference
-------------

.. autofunction:: pvss.qr.create_qr_params

.. autofunction:: pvss.ristretto_255.create_ristretto_255_parameters

.. autoclass:: pvss.Pvss
   :members:
