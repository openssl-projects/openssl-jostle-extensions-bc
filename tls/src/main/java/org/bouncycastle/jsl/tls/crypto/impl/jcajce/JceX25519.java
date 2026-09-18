package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.jsl.tls.crypto.TlsAgreement;
import org.bouncycastle.jsl.tls.crypto.TlsSecret;

/**
 * Support class for X25519 using the JCE.
 */
public class JceX25519 implements TlsAgreement
{
    protected final JceX25519Domain domain;

    protected KeyPair localKeyPair;
    protected PublicKey peerPublicKey;

    public JceX25519(JceX25519Domain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();

        return domain.encodePublicKey(localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        return domain.calculateECDHAgreement(localKeyPair.getPrivate(), peerPublicKey);
    }
}
