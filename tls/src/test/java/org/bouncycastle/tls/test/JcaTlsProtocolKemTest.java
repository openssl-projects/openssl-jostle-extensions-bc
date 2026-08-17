package org.bouncycastle.tls.test;

import org.bouncycastle.jsl.test.JslTestProvider;

public class JcaTlsProtocolKemTest
    extends TlsProtocolKemTest
{

    /**
     * ML-KEM is not an approved algorithm, so the FIPS module does not carry it. A junit.framework.TestCase
     * subclass cannot skip via Assume - JUnit38ClassRunner turns that into a failure -
     * so gate the whole class here and return early instead.
     */
    protected void runTest()
        throws Throwable
    {
        if (!JslTestProvider.supports("KeyPairGenerator.ML-KEM-768"))
        {
            return;
        }

        super.runTest();
    }
    public JcaTlsProtocolKemTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
