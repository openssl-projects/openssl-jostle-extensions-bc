package org.bouncycastle.tls.test;

import java.security.SecureRandom;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Runs the {@link TlsRawKeysProtocolTest} scenarios (RFC 7250) against the JCA crypto backend,
 * exercising {@code JcaTlsRawKeyCertificate}.
 */
public class JcaTlsRawKeysProtocolTest
    extends TlsRawKeysProtocolTest
{

    /**
     * the raw-key scenarios are Ed25519/Ed448, so the FIPS module does not carry it. A junit.framework.TestCase
     * subclass cannot skip via Assume - JUnit38ClassRunner turns that into a failure -
     * so gate the whole class here and return early instead.
     */
    protected void runTest()
        throws Throwable
    {
        if (!JslTestProvider.supports("Signature.ED25519"))
        {
            return;
        }

        super.runTest();
    }
    protected TlsCrypto createCrypto()
    {
        return new JcaTlsCryptoProvider().setProvider(JslTestProvider.provider()).create(new SecureRandom());
    }
}
