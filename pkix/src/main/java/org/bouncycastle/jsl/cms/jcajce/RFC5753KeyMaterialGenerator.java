package org.bouncycastle.jsl.cms.jcajce;

import java.io.IOException;

import org.bouncycastle.jsl.asn1.ASN1Encoding;
import org.bouncycastle.jsl.asn1.cms.ecc.ECCCMSSharedInfo;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.util.Exceptions;
import org.bouncycastle.jsl.util.Pack;

class RFC5753KeyMaterialGenerator
    implements KeyMaterialGenerator
{
    public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
    {
        ECCCMSSharedInfo eccInfo = new ECCCMSSharedInfo(keyAlgorithm, userKeyMaterialParameters, Pack.intToBigEndian(keySize));

        try
        {
            return eccInfo.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("Unable to create KDF material", e);
        }
    }
}
