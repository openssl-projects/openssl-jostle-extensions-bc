package org.bouncycastle.jsl.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * CMS EnvelopedData with the RFC 9629 {@code id-alg-cek-hkdf-sha256} content-encryption-key
 * derivation enabled ({@link JceCMSContentEncryptorBuilder#setEnableSha256HKdf}). This drives the
 * HKDF-SHA256 step now routed through JSL/OpenSSL's native {@code SecretKeyFactory("HKDF-SHA256")}
 * on both sides — {@code applyKdf} (generation) and {@code EnvelopedDataHelper}'s
 * {@code id-alg-cek-hkdf-sha256} branch (recovery) — wrapped in an ML-KEM recipient with AES-256-GCM
 * content. Round-tripping the content proves the two HKDF paths agree.
 */
public class CmsHkdfCekEnvelopedDataTest
    extends JostleProviderTestBase
{
    @Test
    public void hkdfCekEnvelopedRoundTrip()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();

        byte[] keyId = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] data = "envelope me with an HKDF-derived CEK".getBytes("UTF-8");

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
            new JceKEMRecipientInfoGenerator(keyId, kp.getPublic(), CMSAlgorithm.AES256_WRAP).setProvider(JSL));

        CMSEnvelopedData enveloped = gen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM)
                .setEnableSha256HKdf(true)            // RFC 9629 id-alg-cek-hkdf-sha256
                .setProvider(JSL)
                .build());

        CMSEnvelopedData parsed = new CMSEnvelopedData(enveloped.getEncoded());
        boolean any = false;
        for (Object o : parsed.getRecipientInfos().getRecipients())
        {
            RecipientInformation ri = (RecipientInformation)o;
            byte[] recovered = ri.getContent(new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(JSL));
            assertTrue("HKDF-CEK enveloped content did not round-trip", Arrays.areEqual(data, recovered));
            any = true;
        }
        assertTrue("no recipients present", any);
    }
}
