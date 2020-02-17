.. _usecases:

Use Cases
=========
The generic use case of PVSS is to create a secure and durable backup of some highly valuable
information.

.. _usecases.keys:

Offline backup for cryptographic keys
-------------------------------------
Many applications utilize `public-key cryptography
<https://en.wikipedia.org/wiki/Public-key_cryptography>`_ and require a private key for their
operation. Examples are Certificate Authorities, SSH clients, email users and web servers.

If a private key is disclosed, a lot of damage can be done, e.g. issuing false certificates,
signing into SSH servers, faking email signatures or impersonating a web application to
intercept data. That means that private keys must be kept private. One approach is to store the
key on some Hardware Security Module which will carry out the cryptographic operations but won't
allow to create a copy of the key.

On the other hand, private keys must stay available. Through hardware defects or human mistakes
a private key can be easily destroyed, meaning one can no longer issue new certificates, logon
to a SSH server, sign or decrypt emails or operate the web server.

For web servers, there is a trivial solution: If the private key is disclosed, revoke its
certificate.  If the key is destroyed, simply create a new private key and issue a new
certificate.

For the other use cases, there is no easy solution. But the next best thing is PVSS:

When generating a new private key, PVSS is used to create a random secret. The private key is
encrypted symmetrically with this secret, e.g. with AES-GCM. The random secret is split among
:math:`n` semi-trusted users. It is defined that any :math:`1 \lt t \lt n` of those users can
cooperate to reassemble the secret.

Once access to the private key is needed, a special receiver user is created. :math:`t` of the
users need to re-encrypt their key shares with the receiver's public key. Only the receiver can
then reassemble and decrypt the private key. The key could be stored directly into some HSM and
then wiped from the receiver's memory.

.. _usecases.data:

Backup of arbitrary data
------------------------
Similarly, arbitrary data can be backupped securely. For each new backup job, PVSS is used to
create and split a new random secret which is used to symmetrically encrypt (e.g. AES-GCM) the
backupped data.  The encrypted data (along with the PVSS files) is then stored with high
durability in mind.

For restoring the data, any :math:`1 \lt t \lt n` of the users cooperate to reassemble the
secret key.
