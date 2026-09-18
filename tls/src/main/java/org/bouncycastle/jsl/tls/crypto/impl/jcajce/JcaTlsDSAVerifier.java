package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.jsl.tls.DigitallySigned;
import org.bouncycastle.jsl.tls.HashAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.crypto.TlsStreamVerifier;

/**
 * Implementation class for the verification of the raw DSA signature type using the JCA.
 */
public class JcaTlsDSAVerifier
    extends JcaTlsDSSVerifier
{
    public JcaTlsDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.dsa, "NoneWithDSA");
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();

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
            return crypto.createStreamVerifier(digitallySigned, publicKey);
        }

        return null;
    }
}
