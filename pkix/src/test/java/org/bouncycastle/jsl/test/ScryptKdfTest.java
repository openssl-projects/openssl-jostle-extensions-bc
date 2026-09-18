package org.bouncycastle.jsl.test;

import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import org.openssl.jostle.jcajce.spec.ScryptKeySpec;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The scrypt key-derivation path, routed through JSL's native {@code SecretKeyFactory("SCRYPT")}.
 * <p>
 * Two things: the native derivation reproduces the RFC 7914 sec. 12 known-answer vector, and the
 * factory takes JSL's own spec only. The PBES2, PKCS#8 and PKCS#12 builders in this fork construct
 * the JSL spec; BouncyCastle's same-named class is refused, which is what stops a caller reaching
 * this factory with a spec whose parameters it would not read.
 * <p>
 * N=16384, the RFC's own parameters, so it runs in modest memory.
 */
public class ScryptKdfTest
    extends JostleProviderTestBase
{
    @Before
    public void gateOnProviderCapability()
    {
        JslTestProvider.assumeAlgorithm("SecretKeyFactory.SCRYPT");
    }

    // RFC 7914, section 12: scrypt("pleaseletmein","SodiumChloride", N=16384, r=8, p=1, dkLen=64)
    private static final char[] PASSWORD = "pleaseletmein".toCharArray();
    private static final byte[] SALT = Strings.toByteArray("SodiumChloride");
    private static final int N = 16384, R = 8, P = 1, DK_BITS = 512;
    private static final byte[] EXPECTED = Hex.decode(
        "7023bdcb3afd7348461c06cd81fd38eb" + "fda8fbba904f8e3ea9b543f6545da1f2" +
        "d5432955613f0fcf62d49705242a9af9" + "e61e85dc0d651e40dfcf017b45575887");

    @Test
    public void scryptNativeMatchesRfc7914Vector()
        throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT", JSL);

        SecretKey key = factory.generateSecret(new ScryptKeySpec(PASSWORD, SALT, N, R, P, DK_BITS));

        assertTrue("JSL native scrypt must match RFC 7914 vector",
            Arrays.areEqual(EXPECTED, key.getEncoded()));
    }

    @Test
    public void bouncyCastlesScryptSpecIsRefused()
        throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT", JSL);

        try
        {
            factory.generateSecret(
                new org.bouncycastle.jsl.jcajce.spec.ScryptKeySpec(PASSWORD, SALT, N, R, P, DK_BITS));
            fail("a foreign scrypt spec was accepted");
        }
        catch (InvalidKeySpecException e)
        {
            assertTrue("refusal did not name the spec it was handed: " + e.getMessage(),
                e.getMessage().contains("org.bouncycastle.jsl.jcajce.spec.ScryptKeySpec"));
        }
    }
}
