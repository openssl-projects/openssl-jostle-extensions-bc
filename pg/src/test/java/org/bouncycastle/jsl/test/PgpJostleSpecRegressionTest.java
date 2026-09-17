package org.bouncycastle.jsl.test;

import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPS2KCalculator;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * The OpenPGP operators that hand JSL a parameter spec or ask it for a named generator.
 * <p>
 * Argon2 S2K goes through JSL's Argon2KeySpec, and the Ed/X key pairs are generated with JSL's
 * EdDSAParameterSpec and by service name for X25519/X448, which JSL registers individually with no
 * generic "XDH" generator to initialise.
 */
public class PgpJostleSpecRegressionTest
{
    private static final char[] PASSPHRASE = "regression passphrase".toCharArray();

    @BeforeClass
    public static void installProvider()
    {
        JslTestProvider.install();
    }

    @Test
    public void argon2S2kDerivesAKeyOfTheLengthAsked()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("SecretKeyFactory.ARGON2");

        // 1 pass, 4 lanes, 2^16 KiB: RFC 9106's shape at a memory cost a test can afford.
        S2K s2k = new S2K(new S2K.Argon2Params(1, 4, 16, new SecureRandom()));

        byte[] key = new JcePGPS2KCalculator().setProvider(JslTestProvider.name())
            .makeKey(PASSPHRASE, s2k, 32);

        assertEquals("Argon2 S2K did not derive the key length asked for", 32, key.length);

        byte[] again = new JcePGPS2KCalculator().setProvider(JslTestProvider.name())
            .makeKey(PASSPHRASE, s2k, 32);
        assertTrue("the same passphrase and S2K must derive the same key",
            org.bouncycastle.util.Arrays.areEqual(key, again));
    }

    @Test
    public void edKeyPairsGenerateThroughJostlesSpec()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.Ed25519", "KeyPairGenerator.Ed448");

        PGPKeyPairGenerator gen = generatorFor(PublicKeyPacket.VERSION_6);

        assertTag(PublicKeyAlgorithmTags.Ed25519, gen.generateEd25519KeyPair());
        assertTag(PublicKeyAlgorithmTags.Ed448, gen.generateEd448KeyPair());
    }

    @Test
    public void xKeyPairsGenerateByServiceName()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.X25519", "KeyPairGenerator.X448");

        PGPKeyPairGenerator gen = generatorFor(PublicKeyPacket.VERSION_6);

        assertTag(PublicKeyAlgorithmTags.X25519, gen.generateX25519KeyPair());
        assertTag(PublicKeyAlgorithmTags.X448, gen.generateX448KeyPair());
    }

    /**
     * The v4 legacy pair takes the same two paths and is the only caller of the legacy tags, so it
     * would not be covered by the v6 cells above.
     */
    @Test
    public void legacyV4KeyPairsTakeTheSamePaths()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.Ed25519", "KeyPairGenerator.X25519");

        PGPKeyPairGenerator gen = generatorFor(PublicKeyPacket.VERSION_4);

        assertTag(PublicKeyAlgorithmTags.EDDSA_LEGACY, gen.generateLegacyEd25519KeyPair());
        assertTag(PublicKeyAlgorithmTags.ECDH, gen.generateLegacyX25519KeyPair());
    }

    private static PGPKeyPairGenerator generatorFor(int version)
    {
        return new JcaPGPKeyPairGeneratorProvider()
            .setProvider(JslTestProvider.name())
            .get(version, new Date());
    }

    private static void assertTag(int expectedAlgorithm, PGPKeyPair pair)
    {
        assertNotNull("no key pair generated", pair);
        assertEquals("wrong public-key algorithm tag",
            expectedAlgorithm, pair.getPublicKey().getAlgorithm());
    }
}
