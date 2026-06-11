package org.bouncycastle.tls.test;

public class JcaTlsProtocolKemTest
    extends TlsProtocolKemTest
{
    public JcaTlsProtocolKemTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
