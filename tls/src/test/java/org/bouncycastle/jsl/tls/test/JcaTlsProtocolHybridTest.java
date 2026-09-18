package org.bouncycastle.jsl.tls.test;

public class JcaTlsProtocolHybridTest
    extends TlsProtocolHybridTest
{
    /*
     * No class-level gate. Each hybrid group needs both of its halves, and which halves exist
     * depends on the loaded FIPS module in both directions - a 3.1.2 module serves X25519 but no
     * ML-KEM, a 3.5.x module the reverse - so the base class asks the crypto per group and skips
     * just that group. The TLS 1.3 server credential is chosen the same way; see
     * JslTls13ServerCredentials.
     */
    public JcaTlsProtocolHybridTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
