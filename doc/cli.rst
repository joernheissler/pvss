Command Line Interface
======================
A single command line utility ``pvss`` is provided to serve as an example on how to use the API.

Generic usage is ``pvss <datadir> <command> [ARGS...]`` where ``datadir`` is some directory
which contains all public messages from the PVSS workflow.

Help for the available commands is included in the tool: ``pvss --help``

.. _cli.example:

Example
-------
The following sequence of shell commands is executed by six different users who
share a data directory. E.g. use git to synchronize it between the users. All
files inside ``datadir`` are public. All files outside of it are private.

.. code-block:: console

    (init)     $ pvss datadir genparams rst255 
    (alice)    $ pvss datadir genuser Alice alice.key 
    (boris)    $ pvss datadir genuser Boris boris.key 
    (chris)    $ pvss datadir genuser Chris chris.key 
    (dealer)   $ pvss datadir splitsecret 2 secret0.der 
    (receiver) $ pvss datadir genreceiver recv.key 
    (boris)    $ pvss datadir reencrypt boris.key 
    (alice)    $ pvss datadir reencrypt alice.key 
    (receiver) $ pvss datadir reconstruct recv.key secret1.der 

``secret0.der`` and ``secret1.der`` should compare equal.
The *dealer* and *receiver* can encrypt an actual payload by using that file as a shared key.

Directory Structure
-------------------
The ``datadir`` is made up of:

* ``parameters`` - Cryptographic group and other parameters (``SystemParameters``).
* ``users`` - Directory with random file names for each user public key (``PublicKey``).
* ``shares`` - Shared of the secret (``SharedSecret``).
* ``receiver``  - Receiver's public key (``PublicKey``).
* ``reencrypted`` - Directory with random file names for re-encrypted shares (``ReencryptedShare``).
