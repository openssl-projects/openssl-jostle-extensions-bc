package org.bouncycastle.jsl.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.jsl.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyPacket;
import org.bouncycastle.jsl.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jsl.jcajce.CompositePublicKey;
import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPKeyPair;
import org.bouncycastle.jsl.openpgp.api.OpenPGPApi;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.jsl.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.openssl.jostle.jcajce.interfaces.MLDSAKey;
import org.openssl.jostle.jcajce.interfaces.MLKEMKey;
import org.openssl.jostle.jcajce.interfaces.SLHDSAKey;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;
import org.openssl.jostle.jcajce.spec.SLHDSAParameterSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * OpenPGP post-quantum keys when the default random reports 128-bit strength, as {@code new SecureRandom()} does
 * on Windows from Java 9 (the JDK's default DRBG). The provider refuses such a random for the parameter sets
 * above 128 bits, so a random the caller did not choose must not reach it. Here the fork's default random is set
 * to the JDK's default DRBG for the duration of each test.
 */
public class PqcKeysWithA128BitRandomTest
{

    @Rule
    public TestName testName = new TestName();
    private static final byte[] PLAINTEXT = Strings.toUTF8ByteArray("post-quantum, weak default random\n");

    private SecureRandom drbg;

    @Before
    public void setUp()
    {
        JslTestProvider.install();
        drbg = jdkDrbg128();
        CryptoServicesRegistrar.setSecureRandom(drbg);
    }

    @After
    public void tearDown()
    {
        CryptoServicesRegistrar.setSecureRandom(null);
    }

    @Test
    public void keyPairsGenerateWithNoRandomSet()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.SLH-DSA", "KeyGenerator.ML-KEM",
            "Signature.Ed25519", "Signature.Ed448", "KeyAgreement.X25519", "KeyAgreement.X448");

        PGPKeyPairGenerator gen = new JcaPGPKeyPairGeneratorProvider().setProvider(JslTestProvider.provider())
            .get(PublicKeyPacket.VERSION_6, new Date());

        checkMLDSA(gen.generateMLDSA65Ed25519KeyPair(), PublicKeyAlgorithmTags.MLDSA65_Ed25519,
            MLDSAParameterSpec.ml_dsa_65);
        checkMLDSA(gen.generateMLDSA87Ed448KeyPair(), PublicKeyAlgorithmTags.MLDSA87_Ed448,
            MLDSAParameterSpec.ml_dsa_87);
        checkMLKEM(gen.generateMLKEM768X25519KeyPair(), PublicKeyAlgorithmTags.MLKEM768_X25519,
            MLKEMParameterSpec.ml_kem_768);
        checkMLKEM(gen.generateMLKEM1024X448KeyPair(), PublicKeyAlgorithmTags.MLKEM1024_X448,
            MLKEMParameterSpec.ml_kem_1024);

        PGPKeyPair slhdsa = gen.generateSLHDSAShake256sKeyPair();
        assertEquals("SLH-DSA-SHAKE-256s key algorithm", PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s,
            slhdsa.getPublicKey().getAlgorithm());
        PublicKey slhdsaKey = converter().getPublicKey(slhdsa.getPublicKey());
        assertTrue("an SLH-DSA key", slhdsaKey instanceof SLHDSAKey);
        assertEquals("SLH-DSA parameter set", SLHDSAParameterSpec.slh_dsa_shake_256s.getName(),
            ((SLHDSAKey)slhdsaKey).getParameterSpec().getName());
    }

    @Test
    public void theApiGeneratesAKeyAndEncryptsToItWithNoRandomSet()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "KeyGenerator.ML-KEM", "Signature.Ed25519",
            "KeyAgreement.X25519", "MessageDigest.SHA3-256");

        OpenPGPApi api = new JcaOpenPGPApi(JslTestProvider.provider());
        OpenPGPKey key = api.generateKey(new Date()).mlDsa65Ed25519MlKem768X25519Key("Weak <weak@example.org>")
            .build();
        assertEquals("encryption subkey algorithm", PublicKeyAlgorithmTags.MLKEM768_X25519,
            key.getEncryptionKeys().get(0).getAlgorithm());

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage().setArmored(true)
            .addEncryptionCertificate(key.toCertificate()).setAllowPadding(false);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream msgOut = gen.open(bOut);
        msgOut.write(PLAINTEXT);
        msgOut.close();

        OpenPGPMessageInputStream plainIn = api.decryptAndOrVerifyMessage().addDecryptionKey(key)
            .process(new ByteArrayInputStream(bOut.toByteArray()));
        byte[] plain = Streams.readAll(plainIn);
        plainIn.close();
        assertTrue("the message did not decrypt to the plaintext", Arrays.areEqual(PLAINTEXT, plain));
    }

    /**
     * A random the caller sets is passed as given, and the provider's refusal reaches the caller as the cause.
     * This pins the contract: it passes before and after the change to the defaults.
     */
    @Test
    public void anExplicitlySetWeakRandomIsRefusedWithTheProvidersCause()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.Ed25519");
        assumeTrue("a FIPS module draws its own entropy and does not check the caller's", !JslTestProvider.isFips());

        PGPKeyPairGenerator gen = new JcaPGPKeyPairGeneratorProvider().setProvider(JslTestProvider.provider())
            .setSecureRandom(drbg).get(PublicKeyPacket.VERSION_6, new Date());
        try
        {
            gen.generateMLDSA65Ed25519KeyPair();
            fail("a 128-bit random was accepted for ML-DSA-65");
        }
        catch (PGPException e)
        {
            assertTrue("cause " + e.getCause(), e.getCause() instanceof InvalidAlgorithmParameterException);
            assertTrue(e.getCause().getMessage(), e.getCause().getMessage().indexOf("requires 192") >= 0);
        }
    }

    private static void checkMLDSA(PGPKeyPair keyPair, int algorithm, MLDSAParameterSpec spec)
        throws PGPException
    {
        assertEquals(spec.getName() + " key algorithm", algorithm, keyPair.getPublicKey().getAlgorithm());
        PublicKey pq = postQuantumComponent(converter().getPublicKey(keyPair.getPublicKey()));
        assertTrue("an ML-DSA component", pq instanceof MLDSAKey);
        assertEquals("ML-DSA parameter set", spec.getName(), ((MLDSAKey)pq).getParameterSpec().getName());
    }

    private static void checkMLKEM(PGPKeyPair keyPair, int algorithm, MLKEMParameterSpec spec)
        throws PGPException
    {
        assertEquals(spec.getName() + " key algorithm", algorithm, keyPair.getPublicKey().getAlgorithm());
        PublicKey pq = postQuantumComponent(converter().getPublicKey(keyPair.getPublicKey()));
        assertTrue("an ML-KEM component", pq instanceof MLKEMKey);
        assertEquals("ML-KEM parameter set", spec.getName(), ((MLKEMKey)pq).getParameterSpec().getName());
    }

    /** RFC 9980 composites hold the traditional key first and the post-quantum key second. */
    private static PublicKey postQuantumComponent(PublicKey key)
    {
        assertTrue("a composite key", key instanceof CompositePublicKey);
        return ((CompositePublicKey)key).getPublicKeys().get(1);
    }

    private static JcaPGPKeyConverter converter()
    {
        return new JcaPGPKeyConverter().setProvider(JslTestProvider.provider());
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
