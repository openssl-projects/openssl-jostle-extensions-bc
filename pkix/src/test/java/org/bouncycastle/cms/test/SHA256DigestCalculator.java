package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;


class SHA256DigestCalculator
    implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    }

    public OutputStream getOutputStream()
    {
        return bOut;
    }

    public byte[] getDigest()
    {
        byte[] bytes = bOut.toByteArray();

        bOut.reset();

        try
        {
            MessageDigest sha256 = MessageDigest.getInstance("SHA256");

            return sha256.digest(bytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("cannot create SHA256 digest: " + e.getMessage(), e);
        }
    }
}
