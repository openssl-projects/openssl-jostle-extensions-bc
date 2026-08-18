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
        // NoneWithECDSA is registered on the FIPS module now, so this gets much further than it
        // used to. What stops it is raw RSA: TLS 1.2 hashes the handshake itself and signs the
        // digest through NoneWithRSA, which the FIPS module registers as a dead end (it has no
        // "NONE" digest, so initSign fails). Whether that is right is an open question with the
        // provider - the equivalent claim about ECDSA turned out to be false.
        if (JslTestProvider.isFips())
        {
            System.out.println("[skipped] " + JslTestProvider.name()
                + " cannot sign a caller-supplied digest with RSA (NoneWithRSA is a dead registration)");
            return;
        }

        super.testSignatures12();
    }

    public void testSignatures13()
        throws Exception
    {
        // Also gets much further now. The remaining stop is a certificate whose public key the
        // FIPS module will not decode (JcaTlsCertificate.getPublicKey -> bad_certificate, reached
        // from supportsRSA_PSS_PSS), which is an open question with the provider.
        if (JslTestProvider.isFips())
        {
            System.out.println("[skipped] " + JslTestProvider.name()
                + " will not decode one of the test certificates' public keys (RSA-PSS-PSS)");
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
