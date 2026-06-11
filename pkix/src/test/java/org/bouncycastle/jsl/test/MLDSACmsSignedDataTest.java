package org.bouncycastle.jsl.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * CMS SignedData where the signature is ML-DSA (delegated to OpenSSL via JSL)
 * while the message digest (SHA-256) is taken from the default JDK provider —
 * the canonical JSL split, since jostle does not register a MessageDigest.
 */
public class MLDSACmsSignedDataTest
    extends JostleProviderTestBase
{
    @Test
    public void signedDataRoundTrip()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87", JSL);
        KeyPair kp = kpg.generateKeyPair();
        X509CertificateHolder cert = selfSigned(kp, "ML-DSA-87");

        // digest from the JDK default provider, signature from JSL
        DigestCalculatorProvider digProv = new JcaDigestCalculatorProviderBuilder().build();
        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA-87").setProvider(JSL).build(kp.getPrivate());

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digProv).build(signer, cert));
        gen.addCertificate(cert);

        byte[] content = "the quick brown fox".getBytes("UTF-8");
        CMSSignedData signed = gen.generate(new CMSProcessableByteArray(content), true);

        // re-parse and verify
        CMSSignedData parsed = new CMSSignedData(signed.getEncoded());
        boolean any = false;
        for (Object o : parsed.getSignerInfos().getSigners())
        {
            SignerInformation si = (SignerInformation)o;
            // verify from the public key (cert -> java.security cert conversion would need an
            // X.509 CertificateFactory, which JSL does not provide; the JDK supplies the SHA digest)
            assertTrue("ML-DSA-87 CMS signature did not verify",
                si.verify(new JcaSignerInfoVerifierBuilder(digProv).setProvider(JSL).build(kp.getPublic())));
            any = true;
        }
        assertTrue("no signers present", any);
    }

    private static X509CertificateHolder selfSigned(KeyPair kp, String alg)
        throws Exception
    {
        X500Name dn = new X500Name("CN=JSL CMS " + alg);
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder(alg).setProvider(JSL).build(kp.getPrivate());
        return new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(now), new Date(now - 1000L), new Date(now + 86400000L), dn, kp.getPublic())
            .build(signer);
    }
}
