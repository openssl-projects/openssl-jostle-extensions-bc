package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import org.bouncycastle.jsl.tls.AlertDescription;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.TlsFatalAlert;
import org.bouncycastle.jsl.tls.crypto.TlsSigner;
import org.bouncycastle.jsl.tls.crypto.TlsStreamSigner;

/**
 * JCA base class for the signers implementing the two DSA style algorithms from FIPS PUB 186-4: DSA and ECDSA.
 */
public abstract class JcaTlsDSSSigner
    implements TlsSigner
{
    protected final JcaTlsCrypto crypto;
    protected final PrivateKey privateKey;
    protected final short algorithmType;
    protected final String algorithmName;

    protected JcaTlsDSSSigner(JcaTlsCrypto crypto, PrivateKey privateKey, short algorithmType, String algorithmName)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.algorithmType = algorithmType;
        this.algorithmName = algorithmName;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException
    {
        if (algorithm != null && algorithm.getSignature() != algorithmType)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        try
        {
            Signature signer = crypto.getHelper().createSignature(algorithmName);

            signer.initSign(privateKey, crypto.getSecureRandom());
            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                signer.update(hash, 16, 20);
            }
            else
            {
                signer.update(hash, 0, hash.length);
            }
            return signer.sign();
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
        throws IOException
    {
        return null;
    }
}
