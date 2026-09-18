package org.bouncycastle.jsl.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.jsl.asn1.ASN1Encoding;
import org.bouncycastle.jsl.asn1.ASN1Object;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.jsl.operator.DigestCalculator;
import org.bouncycastle.jsl.operator.DigestCalculatorProvider;
import org.bouncycastle.jsl.operator.OperatorCreationException;

class CMPUtil
{
    static byte[] calculateCertHash(ASN1Object obj, AlgorithmIdentifier signatureAlgorithm,
        DigestCalculatorProvider digesterProvider, DigestAlgorithmIdentifierFinder digestAlgFinder)
        throws CMPException
    {
        AlgorithmIdentifier digestAlgorithm = digestAlgFinder.find(signatureAlgorithm);
        if (digestAlgorithm == null)
        {
            throw new CMPException("cannot find digest algorithm from signature algorithm");
        }

        return calculateDigest(obj, digestAlgorithm, digesterProvider);
    }

    static byte[] calculateDigest(ASN1Object obj, AlgorithmIdentifier digestAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        DigestCalculator digestCalculator = getDigestCalculator(digestAlgorithm, digesterProvider);

        derEncodeToStream(obj, digestCalculator.getOutputStream());

        return digestCalculator.getDigest();
    }

    static void derEncodeToStream(ASN1Object obj, OutputStream stream)
    {
        try
        {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        }
        catch (IOException e)
        {
            throw new CMPRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    static DigestCalculator getDigestCalculator(AlgorithmIdentifier digestAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        try
        {
            return digesterProvider.get(digestAlgorithm);
        }
        catch (OperatorCreationException e)
        {
            throw new CMPException("unable to create digester: " + e.getMessage(), e);
        }
    }
}
