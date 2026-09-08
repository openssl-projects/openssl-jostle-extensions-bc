package org.bouncycastle.tls.test;

public class JcaTlsProtocolKemTest
    extends TlsProtocolKemTest
{
    /*
     * No class-level gate. ML-KEM is not absent from JSLFIPS as a matter of policy - it is served
     * or not by the loaded FIPS module (a 3.5.x module serves it, a 3.1.2 one does not), so the
     * base class asks the crypto per group and skips just that group. The TLS 1.3 server
     * credential is chosen the same way; see JslTls13ServerCredentials.
     */
    public JcaTlsProtocolKemTest()
    {
        super(TlsTestUtils.createTestCrypto());
    }
}
