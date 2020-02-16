Data structures
===============
PVSS is a protocol between multiple parties who must exchange a number of messages. Those messages are
`DER <https://en.wikipedia.org/wiki/X.690#DER_encoding>`_ encoded
`ASN.1 <https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One>`_ structures.
This format was chosen because it's well defined and has little overhead. Also,
the zero knowledge proofs require computation of a cryptographic hash. The
input to the hash function needs to be deterministic.

The contents of the messages can be accessed using any standard ASN.1 tools, e.g.:

.. code-block:: console

    $ dumpasn1 -ade message
    $ openssl asn1parse -inform der -in message


Message sizes
-------------
For the Ristretto255 group, typical message sizes are:

* ``Secret``: 36 Bytes.
* ``PreGroupValue``: (up to) 34 Bytes.
* ``ImgGroupValue``: 34 Bytes.
* ``SystemParameters``: 18 Bytes.
* ``PrivateKey``: (up to) 36 Bytes.
* ``PublicKey``: :math:`72 + |name|$` Bytes.
* ``SharedSecret``: (up to) :math:`44 + 34t + 106n + |names|` Bytes.
* ``ReencryptedShare``: (up to) 279 Bytes.

For the ``qr_mod_p`` group, the size depends on the safe prime. With a 4096 bit
prime, the messages are about 12-16 times as large.

Object Identifiers
------------------
Prefix: ``1.3.6.1.4.1.55040.1.0`` (iso.org.dod.internet.private.enterprise.heissler-informatik.floss.pvss)

Parent: https://github.com/joernheissler/oids

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Suffix
     - Description


   * - ``0``
     - ASN.1 module

   * - ``1``
     - Image groups

   * - ``1.0``
     - ``qr_mod_p``: Quadratic residues in multiplicative group modulo safe prime ``p``

   * - ``1.1``
     - ``ristretto_255``: https://ristretto.group/

ASN.1 module
------------
.. code-block::

    PVSS-Module {
        iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
        heissler-informatik(55040) floss(1) pvss(0) id-mod-pvss(0)
    } DEFINITIONS ::=

    BEGIN

    id-pvss OBJECT IDENTIFIER ::= {
        iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
        heissler-informatik(55040) floss(1) pvss(0)
    }

    id-alg OBJECT IDENTIFIER ::= { id-pvss 1 }

    -- A pre group value
    PreGroupValue ::= INTEGER

    -- An image group value; type depends on the algorithm
    ImgGroupValue ::= CHOICE {
        qrValue                 INTEGER,
        ecPoint                 OCTET STRING
    }

    -- System parameters, e.g. the mathematical group
    SystemParameters ::= SEQUENCE {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm
    }

    id-alg-qr OBJECT IDENTIFIER ::= { id-alg 0 }
    SystemParametersQr ::=      INTEGER

    id-alg-rst255 OBJECT IDENTIFIER ::= { id-alg 1 }
    SystemParametersRst255 ::=  NULL

    -- A user's public key
    PublicKey ::= SEQUENCE {
        name                    UTF8String,
        pub0                    ImgGroupValue,
        pub1                    ImgGroupValue
    }

    -- A user's private key
    PrivateKey ::= SEQUENCE {
        priv                    PreGroupValue
    }

    -- Secret that is split and reconstructed
    Secret ::= SEQUENCE {
        secret                  ImgGroupValue
    }

    -- Per user values of SharedSecret
    Share ::= SEQUENCE {
        pub                     UTF8String,
        share                   ImgGroupValue,
        responseF0              PreGroupValue,
        responseF1              PreGroupValue
    }

    -- Sequence of per user values of SharedSecret
    Shares ::= SEQUENCE OF Share

    -- Commitments for polynomial coefficients
    Coefficients ::= SEQUENCE OF ImgGroupValue

    -- Shares of the secret
    SharedSecret ::= SEQUENCE {
        shares                  Shares,
        coefficients            Coefficients,
        challenge               OCTET STRING
    }

    -- Per user hash input, used for SharesChallenge
    HashInputUser ::= SEQUENCE {
        pub                     PublicKey,
        commitment              ImgGroupValue,
        randomCommitment        ImgGroupValue,
        share                   ImgGroupValue,
        randomShare             ImgGroupValue
    }

    -- Sequence of per user hash input, used for SharesChallenge
    HashInputUsers ::= SEQUENCE OF HashInputUser

    -- Input to hash function, results in SharedSecret.challenge
    SharesChallenge ::= SEQUENCE {
        parameters              SystemParameters,
        coefficients            Coefficients,
        users                   HashInputUsers
    }

    -- Sequence of all public keys, used for ReencryptedChallenge
    PublicKeys ::= SEQUENCE OF PublicKey

    -- Input to hash function, results in ReencryptedShare.challenge
    ReencryptedChallenge ::= SEQUENCE {
        parameters              SystemParameters,
        publicKeys              PublicKeys,
        shares                  SharedSecret,
        receiverPublicKey       PublicKey,
        randPub                 ImgGroupValue,
        randShare               ImgGroupValue,
        randElgA                ImgGroupValue,
        randId                  ImgGroupValue
    }

    -- User's share after re-encryption
    ReencryptedShare ::= SEQUENCE {
        idx                     INTEGER,
        elgA                    ImgGroupValue,
        elgB                    ImgGroupValue,
        responsePriv            PreGroupValue,
        responseV0              PreGroupValue,
        responseV1              PreGroupValue,
        responseW0              PreGroupValue,
        responseW1              PreGroupValue,
        challenge               OCTET STRING
    }

    -- Allows auto detection of a message's purpose
    PvssContainer ::= CHOICE {
        parameters              [0]  SystemParameters,
        privKey                 [1]  PrivateKey,
        userPub                 [2]  PublicKey,
        recvPub                 [3]  PublicKey,
        sharedSecret            [4]  SharedSecret,
        reencryptedShare        [5]  ReencryptedShare
    }

    END
