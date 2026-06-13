package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Runs the {@link TlsRawKeysProtocolTest} scenarios (RFC 7250) against the JCA crypto backend,
 * exercising {@code JcaTlsRawKeyCertificate}.
 */
public class JcaTlsRawKeysProtocolTest
    extends TlsRawKeysProtocolTest
{
    protected TlsCrypto createCrypto()
    {
        return new JcaTlsCryptoProvider().setProvider(new JostleProvider()).create(new SecureRandom());
    }
}
