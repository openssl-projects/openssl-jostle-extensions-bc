package org.bouncycastle.jsl.tls.crypto.impl;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.jsl.tls.DigitallySigned;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.SignatureScheme;
import org.bouncycastle.jsl.tls.TlsUtils;
import org.bouncycastle.jsl.tls.crypto.Tls13Verifier;
import org.bouncycastle.jsl.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.jsl.tls.crypto.TlsVerifier;

public final class LegacyTls13Verifier
    implements TlsVerifier
{
    private final int signatureScheme;
    private final Tls13Verifier tls13Verifier;

    public LegacyTls13Verifier(int signatureScheme, Tls13Verifier tls13Verifier)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException("'signatureScheme'");
        }
        if (tls13Verifier == null)
        {
            throw new NullPointerException("'tls13Verifier' cannot be null");
        }

        this.signatureScheme = signatureScheme;
        this.tls13Verifier = tls13Verifier;
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || SignatureScheme.from(algorithm) != signatureScheme)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        final byte[] signature = digitallySigned.getSignature();

        return new TlsStreamVerifier()
        {
            public OutputStream getOutputStream() throws IOException
            {
                return tls13Verifier.getOutputStream();
            }

            public boolean isVerified() throws IOException
            {
                return tls13Verifier.verifySignature(signature);
            }
        };
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }
}
