package org.bouncycastle.jsl.tls.test;

import org.bouncycastle.jsl.test.JslTestProvider;

public class JcaTlsProtocolXDHTest
    extends TlsProtocolXDHTest
{

    /**
     * X25519/X448 registration under JSLFIPS depends on the loaded module: a 3.1.2 module serves
     * them, a 3.5.x module does not, and the provider probes the module at construction. This
     * probe follows automatically. A junit.framework.TestCase
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
