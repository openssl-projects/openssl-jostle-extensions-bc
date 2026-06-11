package org.bouncycastle.jsl.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * End-to-end: build and verify an ML-DSA X.509 certificate where every
 * cryptographic operation is delegated to OpenSSL through the JSL provider.
 * Exercises core (asn.1 / x509) + pkix (cert builder, operator) + JSL.
 */
public class MLDSACertTest
    extends JostleProviderTestBase
{
    @Test
    public void selfSignedCertBuildsAndVerifies()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", JSL);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=JSL Test ML-DSA-65");
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(now), new Date(now - 1000L), new Date(now + 86400000L), dn, kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA-65").setProvider(JSL).build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        assertEquals("unexpected signature algorithm",
            NISTObjectIdentifiers.id_ml_dsa_65, holder.getSignatureAlgorithm().getAlgorithm());

        ContentVerifierProvider vp = new JcaContentVerifierProviderBuilder().setProvider(JSL).build(kp.getPublic());
        assertTrue("ML-DSA-65 certificate signature did not verify", holder.isSignatureValid(vp));
    }

    @Test
    public void tamperedCertFailsVerification()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", JSL);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=JSL Tamper Test");
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(now), new Date(now - 1000L), new Date(now + 86400000L), dn, kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA-44").setProvider(JSL).build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        // verify against a different key -> must fail
        KeyPair other = kpg.generateKeyPair();
        ContentVerifierProvider vp = new JcaContentVerifierProviderBuilder().setProvider(JSL).build(other.getPublic());
        assertFalse("signature unexpectedly verified against wrong key", holder.isSignatureValid(vp));
    }
}
