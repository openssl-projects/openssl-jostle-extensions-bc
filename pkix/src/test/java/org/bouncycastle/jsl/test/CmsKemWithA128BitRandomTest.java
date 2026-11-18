package org.bouncycastle.jsl.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.jsl.cms.CMSAlgorithm;
import org.bouncycastle.jsl.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.jsl.cms.CMSException;
import org.bouncycastle.jsl.cms.CMSProcessableByteArray;
import org.bouncycastle.jsl.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.jsl.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jsl.util.Strings;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * A CMS ML-KEM recipient given a random that reports 128-bit strength, which is what {@code new SecureRandom()}
 * gives on Windows from Java 9. The random is the caller's choice, so it is passed as given and the provider's
 * refusal reaches the caller as the cause. This pins the contract: it passes before and after the change.
 */
public class CmsKemWithA128BitRandomTest
{
    @Test
    public void anExplicitlySetWeakRandomIsRefusedWithTheProvidersCause()
        throws Exception
    {
        JslTestProvider.install();
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.ML-KEM-768");
        assumeTrue("a FIPS module draws its own entropy and does not check the caller's", !JslTestProvider.isFips());

        SecureRandom drbg;
        try
        {
            drbg = SecureRandom.getInstance("DRBG");
        }
        catch (NoSuchAlgorithmException e)
        {
            assumeTrue("no DRBG SecureRandom on this JDK", false);
            return;
        }
        assertTrue("the default DRBG reports 128-bit strength", reportedParameters(drbg).startsWith("128,"));

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", JslTestProvider.name()).generateKeyPair();
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(new byte[]{ 1, 2, 3, 4 }, kp.getPublic(),
            CMSAlgorithm.AES256_WRAP).setProvider(JslTestProvider.name()).setSecureRandom(drbg));
        try
        {
            gen.generate(new CMSProcessableByteArray(Strings.toUTF8ByteArray("weak random")),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider(JslTestProvider.name())
                    .build());
            fail("a 128-bit random was accepted for ML-KEM-768");
        }
        catch (CMSException e)
        {
            Throwable cause = e;
            while (cause.getCause() != null && !(cause instanceof InvalidAlgorithmParameterException))
            {
                cause = cause.getCause();
            }
            assertTrue("no provider refusal in the cause chain of " + e,
                cause instanceof InvalidAlgorithmParameterException);
            assertTrue(cause.getMessage(), cause.getMessage().indexOf("requires 192") >= 0);
        }
    }

    /** SecureRandom.getParameters() is Java 9 and later; these tests also compile for Java 8. */
    private static String reportedParameters(SecureRandom random)
    {
        try
        {
            return String.valueOf(SecureRandom.class.getMethod("getParameters").invoke(random));
        }
        catch (Exception e)
        {
            throw new IllegalStateException("cannot read the SecureRandom parameters", e);
        }
    }
}
