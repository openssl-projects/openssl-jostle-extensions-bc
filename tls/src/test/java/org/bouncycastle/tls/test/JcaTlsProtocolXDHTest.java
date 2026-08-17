package org.bouncycastle.tls.test;

import org.bouncycastle.jsl.test.JslTestProvider;

public class JcaTlsProtocolXDHTest
    extends TlsProtocolXDHTest
{

    /**
     * X25519/X448 are not approved, so the FIPS module does not carry it. A junit.framework.TestCase
     * subclass cannot skip via Assume - JUnit38ClassRunner turns that into a failure -
     * so gate the whole class here and return early instead.
     */
    protected void runTest()
        throws Throwable
    {
        if (!JslTestProvider.supports("KeyAgreement.X25519"))
        {
            return;
        }

        super.runTest();
    }
    public JcaTlsProtocolXDHTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
