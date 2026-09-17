package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.DefaultProviderName;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Exceptions;

class SHA1PGPDigestCalculator
    implements PGPDigestCalculator
{
    private MessageDigest digest;

    SHA1PGPDigestCalculator()
    {
        try
        {
            String providerName = DefaultProviderName.getProviderName();
            digest = providerName == null
                ? MessageDigest.getInstance("SHA1")
                : MessageDigest.getInstance("SHA1", providerName);
        }
        catch (GeneralSecurityException e)
        {
            // Widened from NoSuchAlgorithmException: naming a provider adds NoSuchProviderException,
            // and this constructor declares neither.
            throw Exceptions.illegalStateException("cannot find SHA-1", e);
        }
    }

    public int getAlgorithm()
    {
        return HashAlgorithmTags.SHA1;
    }

    public OutputStream getOutputStream()
    {
        return OutputStreamFactory.createStream(digest);
    }

    public byte[] getDigest()
    {
        return digest.digest();
    }

    public void reset()
    {
        digest.reset();
    }
}
