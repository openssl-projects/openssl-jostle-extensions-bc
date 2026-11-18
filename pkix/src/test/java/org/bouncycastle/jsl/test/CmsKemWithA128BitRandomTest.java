package org.bouncycastle.jsl.test;

import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jsl.cms.CMSAlgorithm;
import org.bouncycastle.jsl.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.jsl.cms.CMSException;
import org.bouncycastle.jsl.cms.CMSProcessableByteArray;
import org.bouncycastle.jsl.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.jsl.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jsl.util.Strings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import static org.junit.Assert.assertEquals;
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

    @Rule
    public TestName testName = new TestName();
    @Test
    public void anExplicitlySetWeakRandomIsRefusedWithTheProvidersCause()
        throws Exception
    {
        JslTestProvider.install();
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.ML-KEM-768");
        assumeTrue("a FIPS module draws its own entropy and does not check the caller's", !JslTestProvider.isFips());

        SecureRandom drbg = jdkDrbg128();

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

    /**
     * The JDK's own DRBG at its default configuration: the default random on Windows from Java 9, reporting 128-bit
     * strength. Asked of SUN by name, so that the provider under test, which registers a DRBG of its own, cannot
     * stand in for it. Java 8 has none, and its default random reports no strength, so the case does not arise.
     */
    private SecureRandom jdkDrbg128()
    {
        SecureRandom random;
        try
        {
            random = SecureRandom.getInstance("DRBG", "SUN");
        }
        catch (GeneralSecurityException e)
        {
            skip("the JDK has no DRBG SecureRandom (Java 8), so its default reports no strength and the provider"
                + " checks none");
            return null;
        }
        String parameters = reportedParameters(random);
        if (parameters == null)
        {
            skip("the JDK cannot report a SecureRandom's strength (Java 8), so the provider checks none");
            return null;
        }
        assertEquals("the JDK's DRBG provider", "SUN", random.getProvider().getName());
        assertEquals("the JDK's DRBG algorithm", "DRBG", random.getAlgorithm());
        assertTrue("the JDK's default DRBG reports 128-bit strength: " + parameters, parameters.startsWith("128,"));
        return random;
    }

    private void skip(String reason)
    {
        System.out.println("[skipped] " + testName.getMethodName() + ": " + reason);
        assumeTrue(reason, false);
    }

    /** SecureRandom.getParameters() is Java 9 and later; these tests also compile for Java 8. Null when absent. */
    private static String reportedParameters(SecureRandom random)
    {
        Method getParameters;
        try
        {
            getParameters = SecureRandom.class.getMethod("getParameters");
        }
        catch (NoSuchMethodException e)
        {
            return null;
        }
        try
        {
            return String.valueOf(getParameters.invoke(random));
        }
        catch (Exception e)
        {
            throw new IllegalStateException("cannot read the SecureRandom parameters", e);
        }
    }
}
