************
ASN.1 module
************

Object Identifiers
==================

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
============

::

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

    PreGroupValue ::= INTEGER

    ImgGroupValue ::= CHOICE {
        qrValue                 INTEGER,
        ecPoint                 OCTET STRING
    }

    SystemParameters ::= SEQUENCE {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm
    }

    id-alg-qr OBJECT IDENTIFIER ::= { id-alg 0 }
    SystemParametersQr ::=      INTEGER

    id-alg-rst255 OBJECT IDENTIFIER ::= { id-alg 1 }
    SystemParametersRst255 ::=  NULL

    PublicKey ::= SEQUENCE {
        name                    UTF8String,
        pub0                    ImgGroupValue,
        pub1                    ImgGroupValue
    }

    PrivateKey ::= SEQUENCE {
        priv                    PreGroupValue
    }

    Secret ::= SEQUENCE {
        secret                  ImgGroupValue
    }

    Share ::= SEQUENCE {
        pub                     UTF8String,
        share                   ImgGroupValue,
        responseX               PreGroupValue,
        responseY               PreGroupValue
    }

    Shares ::= SEQUENCE OF Share

    Coefficients ::= SEQUENCE OF ImgGroupValue

    SharedSecret ::= SEQUENCE {
        shares                  Shares,
        coefficients            Coefficients,
        challenge               OCTET STRING
    }

    HashInputUser ::= SEQUENCE {
        pub                     PublicKey,
        commitment              ImgGroupValue,
        randomCommitment        ImgGroupValue,
        share                   ImgGroupValue,
        randomShare             ImgGroupValue
    }

    HashInputUsers ::= SEQUENCE OF HashInputUser

    SharesChallenge ::= SEQUENCE {
        parameters              SystemParameters,
        coefficients            Coefficients,
        users                   HashInputUsers
    }

    PublicKeys ::= SEQUENCE OF PublicKey

    ReencryptedChallenge ::= SEQUENCE {
        parameters              SystemParameters,
        publicKeys              PublicKeys,
        shares                  SharedSecret,
        receiverPublicKey       PublicKey,
        randC2pub               ImgGroupValue,
        randPub                 ImgGroupValue,
        randC1                  ImgGroupValue,
        randOne                 ImgGroupValue
    }

    ReencryptedShare ::= SEQUENCE {
        idx                     INTEGER,
        c1                      ImgGroupValue,
        c2                      ImgGroupValue,
        responsePriv            PreGroupValue,
        responseA               PreGroupValue,
        responseB               PreGroupValue,
        responseV               PreGroupValue,
        responseW               PreGroupValue,
        challenge               OCTET STRING
    }

    END
