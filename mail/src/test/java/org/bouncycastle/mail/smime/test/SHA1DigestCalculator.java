package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;


class SHA1DigestCalculator
    implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
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
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");

            return sha1.digest(bytes);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("cannot create SHA1 digest: " + e.getMessage(), e);
        }
    }
}
