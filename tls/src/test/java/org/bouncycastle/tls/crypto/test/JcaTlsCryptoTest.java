package org.bouncycastle.tls.crypto.test;

import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JcaTlsCryptoTest
    extends TlsCryptoTest
{

    /*
     * These four exercise algorithms the FIPS module does not carry - the legacy MD5+SHA1
     * combined hash, the SM3 HMAC, and signature schemes covering the full TLS set (Ed25519 among
     * them). Overridden per method rather than gating the class, so the rest of the crypto surface
     * is still checked against JSLFIPS. A junit.framework.TestCase subclass cannot skip via
     * Assume, hence the early return.
     */
    public void testSignaturesLegacy()
        throws Exception
    {
        if (!JslTestProvider.supports("MessageDigest.MD5"))
        {
            return;
        }

        super.testSignaturesLegacy();
    }

    public void testSignatures12()
        throws Exception
    {
        // the real blocker is raw ECDSA: both of these reach
        // JcaTlsECDSA13Signer.generateRawSignature, which needs NoneWithECDSA. Naming it here
        // rather than some other absent algorithm means these start running by themselves the
        // moment the provider registers it.
        if (!JslTestProvider.supports("Signature.NONEwithECDSA"))
        {
            return;
        }

        super.testSignatures12();
    }

    public void testSignatures13()
        throws Exception
    {
        if (!JslTestProvider.supports("Signature.NONEwithECDSA"))
        {
            return;
        }

        super.testSignatures13();
    }

    public void testHKDFExpandLimit()
    {
        if (!JslTestProvider.supports("Mac.HmacSM3"))
        {
            return;
        }

        super.testHKDFExpandLimit();
    }
    static
    {
        // testSignatures13 decodes ML-DSA/SLH-DSA/EdDSA certificate keys via a CertificateFactory,
        // which resolves the SPKI to a PublicKey through the installed providers. JSL must be
        // registered (not merely passed to setProvider) so those keys decode to JSL types with the
        // FIPS-conformant encoding the TLS layer's certificate checks expect.
        JslTestProvider.install();
    }

    public JcaTlsCryptoTest()
    {
        super(new JcaTlsCryptoProvider().setProvider(JslTestProvider.provider()).create(new SecureRandom()));
    }
}
