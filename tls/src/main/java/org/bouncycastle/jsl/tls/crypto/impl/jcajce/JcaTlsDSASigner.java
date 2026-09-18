package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;

import org.bouncycastle.jsl.tls.HashAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.crypto.TlsStreamSigner;

/**
 * Implementation class for generation of the raw DSA signature type using the JCA.
 */
public class JcaTlsDSASigner
    extends JcaTlsDSSSigner
{
    public JcaTlsDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        super(crypto, privateKey, SignatureAlgorithm.dsa, "NoneWithDSA");

        // A FIPS module built with dsa-sign-disabled still imports DSA keys and verifies DSA
        // signatures, and the Signature service stays registered so verification keeps working -
        // only signing is refused, at initSign. Probe it here: otherwise the refusal arrives
        // mid-handshake as an internal_error alert, long after the credential was accepted.
        try
        {
            crypto.getHelper().createSignature(algorithmName).initSign(privateKey, crypto.getSecureRandom());
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalArgumentException("'privateKey' cannot sign with this provider: "
                + e.getMessage(), e);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("'privateKey' cannot be used with " + algorithmName
                + ": " + e.getMessage(), e);
        }
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm)
        throws IOException
    {
        /*
         * Unfortunately "NoneWithDSA" (a.k.a "RawDSA") only works with 20 byte inputs in the SUN
         * provider. Therefore we need to use a stream signer for other cases.
         * 
         * TODO We could do a test run for raw DSA support of other sizes and then resort to the
         * stream signer only when the provider doesn't support wider hashes.
         */
        if (null != algorithm
            && algorithmType == algorithm.getSignature()
            && HashAlgorithm.getOutputSize(algorithm.getHash()) != 20)
        {
            return crypto.createStreamSigner(algorithm, privateKey, true);
        }

        return null;
    }
}
