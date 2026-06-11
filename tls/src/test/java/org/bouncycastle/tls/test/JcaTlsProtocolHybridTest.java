package org.bouncycastle.tls.test;

public class JcaTlsProtocolHybridTest
    extends TlsProtocolHybridTest
{
    public JcaTlsProtocolHybridTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
