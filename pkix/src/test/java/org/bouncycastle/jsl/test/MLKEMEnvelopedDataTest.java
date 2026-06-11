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
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * CMS EnvelopedData using an ML-KEM recipient (encapsulation + AES key-wrap) and
 * AES-256-GCM content encryption — both delegated to OpenSSL through JSL. This is
 * the path that flows through the patched JceCMSKEMKeyWrapper / Unwrapper.
 */
public class MLKEMEnvelopedDataTest
    extends JostleProviderTestBase
{
    @Test
    public void mlkemEnvelopedRoundTrip()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", JSL);
        KeyPair kp = kpg.generateKeyPair();

        byte[] keyId = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] data = "envelope me with ML-KEM".getBytes("UTF-8");

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
            new JceKEMRecipientInfoGenerator(keyId, kp.getPublic(), CMSAlgorithm.AES256_WRAP).setProvider(JSL));

        CMSEnvelopedData enveloped = gen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider(JSL).build());

        CMSEnvelopedData parsed = new CMSEnvelopedData(enveloped.getEncoded());
        boolean any = false;
        for (Object o : parsed.getRecipientInfos().getRecipients())
        {
            RecipientInformation ri = (RecipientInformation)o;
            byte[] recovered = ri.getContent(new JceKEMEnvelopedRecipient(kp.getPrivate()).setProvider(JSL));
            assertTrue("ML-KEM enveloped content did not round-trip", Arrays.areEqual(data, recovered));
            any = true;
        }
        assertTrue("no recipients present", any);
    }
}
