package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tls.SignatureScheme;

public class PQCUtil
{
    public static ASN1ObjectIdentifier getMLDSAObjectidentifier(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.mldsa44:
            return NISTObjectIdentifiers.id_ml_dsa_44;
        case SignatureScheme.mldsa65:
            return NISTObjectIdentifiers.id_ml_dsa_65;
        case SignatureScheme.mldsa87:
            return NISTObjectIdentifiers.id_ml_dsa_87;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static ASN1ObjectIdentifier getSLHDSAObjectidentifier(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.DRAFT_slhdsa_sha2_128s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128s;
        case SignatureScheme.DRAFT_slhdsa_sha2_128f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128f;
        case SignatureScheme.DRAFT_slhdsa_sha2_192s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_192s;
        case SignatureScheme.DRAFT_slhdsa_sha2_192f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_192f;
        case SignatureScheme.DRAFT_slhdsa_sha2_256s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256s;
        case SignatureScheme.DRAFT_slhdsa_sha2_256f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256f;
        case SignatureScheme.DRAFT_slhdsa_shake_128s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128s;
        case SignatureScheme.DRAFT_slhdsa_shake_128f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128f;
        case SignatureScheme.DRAFT_slhdsa_shake_192s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_192s;
        case SignatureScheme.DRAFT_slhdsa_shake_192f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_192f;
        case SignatureScheme.DRAFT_slhdsa_shake_256s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_256s;
        case SignatureScheme.DRAFT_slhdsa_shake_256f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_256f;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static boolean supportsMLDSA(AlgorithmIdentifier pubKeyAlgID, ASN1ObjectIdentifier mlDsaAlgOid)
    {
        return hasOidWithNullParameters(pubKeyAlgID, mlDsaAlgOid);
    }

    public static boolean supportsSLHDSA(AlgorithmIdentifier pubKeyAlgID, ASN1ObjectIdentifier slhDsaAlgOid)
    {
        return hasOidWithNullParameters(pubKeyAlgID, slhDsaAlgOid);
    }

    private static boolean hasOidWithNullParameters(AlgorithmIdentifier algID, ASN1ObjectIdentifier algOid)
    {
        return algID.getAlgorithm().equals(algOid)
            && algID.getParameters() == null;
    }
}
