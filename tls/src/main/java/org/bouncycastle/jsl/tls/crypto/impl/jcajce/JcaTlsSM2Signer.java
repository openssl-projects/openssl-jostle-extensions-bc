package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jsl.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.SignatureScheme;
import org.bouncycastle.jsl.tls.crypto.TlsSigner;
import org.bouncycastle.jsl.tls.crypto.TlsStreamSigner;
import org.bouncycastle.jsl.util.Strings;

/**
 * JCA-based SM2 signer for TLS 1.3 (RFC 8998).
 */
public class JcaTlsSM2Signer
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final byte[] identifier;

    public JcaTlsSM2Signer(JcaTlsCrypto crypto, PrivateKey privateKey, int signatureScheme)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (SignatureScheme.sm2sig_sm3 != signatureScheme)
        {
            throw new IllegalArgumentException(
                "'signatureScheme' " + SignatureScheme.getText(signatureScheme) + " is not SM2");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.identifier = Strings.toByteArray("TLSv1.3+GM+Cipher+Suite");
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
        if (algorithm == null || SignatureScheme.from(algorithm) != SignatureScheme.sm2sig_sm3)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        AlgorithmParameterSpec sm2Spec = new SM2ParameterSpec(identifier);

        return crypto.createStreamSigner("SM3withSM2", sm2Spec, privateKey, true);
    }
}
