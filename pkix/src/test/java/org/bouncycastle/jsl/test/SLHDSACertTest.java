package org.bouncycastle.jsl.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * SLH-DSA self-signed certificate, signed and verified through JSL/OpenSSL.
 */
public class SLHDSACertTest
    extends JostleProviderTestBase
{
    @Test
    public void slhdsaSha2_128f()
        throws Exception
    {
        runCert("SLH-DSA-SHA2-128F");
    }

    @Test
    public void slhdsaShake_192f()
        throws Exception
    {
        runCert("SLH-DSA-SHAKE-192F");
    }

    private void runCert(String alg)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, JSL);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=JSL " + alg);
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder(alg).setProvider(JSL).build(kp.getPrivate());
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(now), new Date(now - 1000L), new Date(now + 86400000L), dn, kp.getPublic())
            .build(signer);

        ContentVerifierProvider vp = new JcaContentVerifierProviderBuilder().setProvider(JSL).build(kp.getPublic());
        assertTrue(alg + " certificate signature did not verify", holder.isSignatureValid(vp));
    }
}
