package org.bouncycastle.tls.test;

public class JcaTlsProtocolHybridKemTest
    extends TlsProtocolHybridKemTest
{
    public JcaTlsProtocolHybridKemTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
