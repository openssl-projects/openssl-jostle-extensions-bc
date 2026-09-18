package org.bouncycastle.jsl.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;

import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jsl.cms.CMSAlgorithm;
import org.bouncycastle.jsl.cms.CMSEnvelopedData;
import org.bouncycastle.jsl.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.jsl.cms.CMSProcessableByteArray;
import org.bouncycastle.jsl.cms.RecipientInformation;
import org.bouncycastle.jsl.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.jsl.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.jsl.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Guards the CMS key-agreement migration: the user keying material reaches JSL through JSL's own
 * UserKeyingMaterialSpec.
 * <p>
 * The recovery half is the load-bearing assertion. A UKM that never reached the agreement is not
 * an error on either side - both ends simply derive a different key-encryption key - so a round
 * trip that carries a UKM on the wire and still recovers is what separates the two.
 * <p>
 * The EC cell is ungated because the EC branch builds a UserKeyingMaterialSpec whether or not a
 * UKM was supplied, so it has to run on every configuration. The XDH cell gates: a FIPS module
 * need not serve the XDH curves.
 * <p>
 * The static-key refusal and the finite-field DH paths are covered by NewEnvelopedDataTest
 * (testStaticStaticDHAgreement, testEphemeralStaticDHAgreement, testOpenSSLVectors).
 */
public class CmsKeyAgreeUkmRegressionTest
    extends JostleProviderTestBase
{
    private static final byte[] UKM = Strings.toByteArray("regression ukm, 32 octets long..");

    @Test
    public void ecKeyAgreeRoundTripsWithUserKeyingMaterial()
        throws Exception
    {
        roundTrip("EC", new ECGenParameterSpec("P-256"), CMSAlgorithm.ECDH_SHA256KDF);
    }

    @Test
    public void xdhKeyAgreeRoundTripsWithUserKeyingMaterial()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.X25519", "KeyAgreement.X25519");

        roundTrip("X25519", null, CMSAlgorithm.ECDH_HKDF_SHA256);
    }

    private void roundTrip(String keyAlgorithm, AlgorithmParameterSpec keyParams, ASN1ObjectIdentifier agreement)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, JSL);
        if (keyParams != null)
        {
            kpg.initialize(keyParams);
        }
        KeyPair originator = kpg.generateKeyPair();
        KeyPair recipient = kpg.generateKeyPair();

        byte[] data = Strings.toByteArray("agree with me");
        byte[] recipientKeyId = new byte[]{1, 2, 3, 4, 5};

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
            new JceKeyAgreeRecipientInfoGenerator(agreement,
                originator.getPrivate(), originator.getPublic(), CMSAlgorithm.AES128_WRAP)
                .setUserKeyingMaterial(UKM)
                .addRecipient(recipientKeyId, recipient.getPublic())
                .setProvider(JSL));

        CMSEnvelopedData enveloped = gen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(JSL).build());

        byte[] encoded = enveloped.getEncoded();
        assertTrue(keyAlgorithm + ": the user keying material was not carried on the wire",
            indexOf(encoded, UKM) >= 0);

        Collection recipients = new CMSEnvelopedData(encoded).getRecipientInfos().getRecipients();
        assertEquals(1, recipients.size());

        RecipientInformation info = (RecipientInformation)recipients.iterator().next();
        assertArrayEquals(keyAlgorithm + ": content did not round-trip through the agreed key",
            data, info.getContent(
                new JceKeyAgreeEnvelopedRecipient(recipient.getPrivate()).setProvider(JSL)));
    }

    private static int indexOf(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.length <= haystack.length; i++)
        {
            if (Arrays.areEqual(needle, Arrays.copyOfRange(haystack, i, i + needle.length)))
            {
                return i;
            }
        }
        return -1;
    }
}
