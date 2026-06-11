package org.bouncycastle.tls.test;

public class JcaTlsProtocolXDHTest
    extends TlsProtocolXDHTest
{
    public JcaTlsProtocolXDHTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
