package org.bouncycastle.jsl.tls.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.tls.SignatureAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.tls.TlsCredentialedSigner;
import org.bouncycastle.jsl.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

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
        // TLS 1.2 signs a caller-supplied digest, so this measures a raw RSA signature rather
        // than a service lookup: a provider can register NoneWithRSA and still refuse it at
        // initSign.
        if (!JslTestProvider.canSign("NoneWithRSA", "RSA", 2048))
        {
            System.out.println("[skipped] " + JslTestProvider.name() + " cannot sign a caller-supplied"
                + " digest with RSA (raw RSA signing unresolved pending a compliance decision)");
            return;
        }

        super.testSignatures12();
    }

    public void testSignatures13()
        throws Exception
    {
        super.testSignatures13();
    }

    /**
     * A FIPS module can be built with {@code dsa-sign-disabled}: DSA keys import and DSA signatures
     * verify, but signing is refused. {@link org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsDSASigner}
     * refuses such a credential when it is loaded, so drop just the DSA case and leave the RSA and
     * ECDSA cases of the calling loop to run.
     */
    protected TlsCredentialedSigner loadCredentialedSigner12(TlsCryptoParameters cryptoParams,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException
    {
        try
        {
            return super.loadCredentialedSigner12(cryptoParams, signatureAndHashAlgorithm);
        }
        catch (IllegalArgumentException e)
        {
            if (SignatureAlgorithm.dsa != signatureAndHashAlgorithm.getSignature())
            {
                throw e;
            }

            System.out.println("[skipped] " + JslTestProvider.name() + " imports DSA keys and"
                + " verifies DSA signatures but cannot sign with them");
            return null;
        }
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
