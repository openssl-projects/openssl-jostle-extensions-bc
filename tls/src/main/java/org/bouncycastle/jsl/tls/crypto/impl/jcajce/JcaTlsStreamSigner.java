package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jsl.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jsl.tls.AlertDescription;
import org.bouncycastle.jsl.tls.TlsFatalAlert;
import org.bouncycastle.jsl.tls.crypto.TlsStreamSigner;

class JcaTlsStreamSigner
    implements TlsStreamSigner
{
    private final Signature signer;
    private final OutputStream output;

    JcaTlsStreamSigner(Signature signer)
    {
        this.signer = signer;
        this.output = OutputStreamFactory.createStream(signer);
    }

    public OutputStream getOutputStream() throws IOException
    {
        return output;
    }

    public byte[] getSignature() throws IOException
    {
        try
        {
            return signer.sign();
        }
        catch (SignatureException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
