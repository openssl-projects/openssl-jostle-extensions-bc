package org.bouncycastle.jsl.test;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Covers the scrypt key-derivation path now routed through JSL's native
 * {@code SecretKeyFactory("SCRYPT")} (OpenSSL). Verifies two things in one go:
 * <ul>
 *   <li>JSL's factory accepts BouncyCastle's {@code org.bouncycastle.jcajce.spec.ScryptKeySpec}
 *       (the type the satellite's PBES2/PKCS#8/PKCS#12 builders construct), and</li>
 *   <li>it produces the RFC 7914 §12 known-answer vector, i.e. the native OpenSSL scrypt agrees
 *       bit-for-bit with the reference.</li>
 * </ul>
 * Uses N=16384 (the RFC vector), so it runs in modest memory.
 */
public class ScryptKdfTest
    extends JostleProviderTestBase
{
    // RFC 7914, section 12: scrypt("pleaseletmein","SodiumChloride", N=16384, r=8, p=1, dkLen=64)
    private static final char[] PASSWORD = "pleaseletmein".toCharArray();
    private static final byte[] SALT = Strings.toByteArray("SodiumChloride");
    private static final int N = 16384, R = 8, P = 1, DK_BITS = 512;
    private static final byte[] EXPECTED = Hex.decode(
        "7023bdcb3afd7348461c06cd81fd38eb" + "fda8fbba904f8e3ea9b543f6545da1f2" +
        "d5432955613f0fcf62d49705242a9af9" + "e61e85dc0d651e40dfcf017b45575887");

    @Test
    public void scryptNativeMatchesRfc7914AndAcceptsBcSpec()
        throws Exception
    {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("SCRYPT", JSL);

        // BouncyCastle's ScryptKeySpec, derived through JSL/OpenSSL.
        SecretKey key = factory.generateSecret(new ScryptKeySpec(PASSWORD, SALT, N, R, P, DK_BITS));

        assertTrue("JSL native scrypt must match RFC 7914 vector",
            Arrays.areEqual(EXPECTED, key.getEncoded()));
    }
}
