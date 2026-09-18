package org.bouncycastle.jsl.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * RFC 9580 v6 PKESK decryption of fixed messages, ported from bc-java's
 * {@code PGPv6MessageDecryptionTest}; the BouncyCastle-operator cells are replaced with the Jce
 * ones, this fork having no {@code *.bc.*} operators.
 * <p>
 * These are the oracle for the hybrid HKDF path: {@code JcaJcePGPUtil} builds Jostle's
 * {@code HybridValueParameterSpec} with T prepended and the {@code OpenPGP X25519}/{@code X448}
 * info string, and Jostle refuses a missing T or an empty info typed. The key, the ciphertext and
 * the plaintext are all fixed, so a wrong T or info fails here rather than agreeing with itself.
 */
public class PgpV6MessageKnownAnswerTest
{
    @BeforeClass
    public static void installProvider()
    {
        JslTestProvider.install();
    }

    @Test
    public void aFixedX25519V6MessageDecryptsToItsKnownPlaintext()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyAgreement.X25519withSHA256HKDF");
        // This message's SEIPDv2 packet is AES-256 with OCB (RFC 9580 AEAD algorithm 2), measured
        // from the packet, so the cipher gates this cell as well as the agreement. Neither FIPS
        // module serves OCB.
        JslTestProvider.assumeCipher("AES/OCB/NoPadding");

        implTestDecrypt(X25519_KEY, X25519_MSG, PublicKeyAlgorithmTags.X25519, "Hello World :)");
    }

    @Test
    public void aFixedX448V6MessageDecryptsToItsKnownPlaintext()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyAgreement.X448withSHA512HKDF");
        // AES-256 with GCM (AEAD algorithm 3) in this one, so it runs wherever the agreement does.
        JslTestProvider.assumeCipher("AES/GCM/NoPadding");

        implTestDecrypt(X448_KEY, X448_MSG, PublicKeyAlgorithmTags.X448, "Hello, World!\n");
    }

    private void implTestDecrypt(String armouredKey, String armouredMessage, int algorithm, String plaintext)
        throws Exception
    {
        PGPSecretKeyRing secretKeys = (PGPSecretKeyRing)readPgp(armouredKey);

        PGPEncryptedDataList encList = (PGPEncryptedDataList)readPgp(armouredMessage);
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);

        assertEquals("PKESK version mismatch", PublicKeyEncSessionPacket.VERSION_6, encData.getVersion());
        assertEquals("public-key algorithm mismatch", algorithm, encData.getAlgorithm());

        PGPSecretKey decryptionKey = secretKeys.getSecretKey(encData.getKeyID());
        assertNotNull("the decryption key is not identifiable", decryptionKey);

        PGPPrivateKey privateKey = decryptionKey.extractPrivateKey(null);
        PublicKeyDataDecryptorFactory decryptor = new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(JslTestProvider.name())
            .build(privateKey);

        InputStream decrypted = encData.getDataStream(decryptor);
        PGPObjectFactory decFac = new JcaPGPObjectFactory(decrypted);
        PGPLiteralData lit = (PGPLiteralData)decFac.nextObject();

        assertTrue("message plaintext mismatch", Arrays.areEqual(
            Strings.toUTF8ByteArray(plaintext), Streams.readAll(lit.getDataStream())));
    }

    private Object readPgp(String armoured)
        throws Exception
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toUTF8ByteArray(armoured));
        ArmoredInputStream aIn = new ArmoredInputStream(bIn);
        BCPGInputStream pIn = new BCPGInputStream(aIn);
        try
        {
            return new JcaPGPObjectFactory(pIn).nextObject();
        }
        finally
        {
            pIn.close();
            aIn.close();
            bIn.close();
        }
    }

    /** X25519 test key from RFC 9580. */
    private static final String X25519_KEY =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB\n" +
                "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ\n" +
                "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh\n" +
                "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe\n" +
                "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/\n" +
                "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG\n" +
                "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6\n" +
                "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE\n" +
                "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr\n" +
                "k0mXubZvyl4GBg==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

    /** Created with rpgpie 0.1.1 (rpgp 0.14.0-alpha.0). */
    private static final String X25519_MSG =
        "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRk5Bu/DU62hzgRm\n" +
                "JYvBYeLA2Nrmz15g69ZN0xAB7SLDRCjjhnK6V7fGns6P1EiSCYbl1uNVBhK0MPGe\n" +
                "rU9FY4yUXTnbB6eIXdCw0loCCQIOu95D17wvJJC2a96ou9SGPIoA4Q2dMH5BMS9Z\n" +
                "veq3AGgIBdJMF8Ft8PBE30R0cba1O5oQC0Eiscw7fkNnYGuSXagqNXdOBkHDN0fk\n" +
                "VWFrxQRbxEVYUWc=\n" +
                "=u2kL\n" +
                "-----END PGP MESSAGE-----\n";

    /** Ed448/X448 test key, courtesy of @twiss from Proton. */
    private static final String X448_KEY =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "xX0GZrnFtRwAAAA5wl2q+bhfNkzHsxlLowaUy0sTOeAsmhseHBvPKKc7yehR\n" +
                "8Qs93LbjQHjw3IaqduMRDRs4pZJyV/+AACKFtkkC3ebcyaOvHGaJpc9rx0Z1\n" +
                "4YHdd4BG1AJvZuhk8pJ6dQuuQeFtBsQctoktFwlDh0XjnjUrkMLALQYfHAoA\n" +
                "AABMBYJmucW1AwsJBwUVCAoMDgQWAAIBApsDAh4JIqEGEvURGalOLHznAmcI\n" +
                "MRsEHorGZ2ikxHawiPyOMw+CAOANJwkDBwMJAQcBCQIHAgAAAACbfCBvUoq6\n" +
                "bon1bSsp9HLc829xjDINBOvegmk4tMKv392c1LNPJacojQ46YZpkNVhE4sSx\n" +
                "Gf/vdUqh62KP+vwm5cXs/f11WmdVnclv7uR9s3a1GI79lwOJiuw3AIXA3VjR\n" +
                "+AhmeoAFJRfcjfT3hwwkBdu8E3BQ+1bGqfXGhOPYcDTJOO+vMExGSTEk+A9j\n" +
                "DmWnW6snAMd7Bma5xbUaAAAAOAPvCJKYxSQ+SfLb313/tC9N2tGF00x6YJkz\n" +
                "JLqLKVDofMHmUC1f8IJFtQ3cLMDhHVY0VxffLXT1AEffhVpafxBdelL69esq\n" +
                "2zQtDp5l8Hx7D/sU+W3+KmGLnRki72g7gfoQuio+wk8UcHmfwYm7AHvuwsAN\n" +
                "BhgcCgAAACwFgma5xbUCmwwioQYS9REZqU4sfOcCZwgxGwQeisZnaKTEdrCI\n" +
                "/I4zD4IA4AAAAACQUiBvjI1gFe4O/GDPwIoX8YSK/qP3IsMAwvidXclpmlLN\n" +
                "RzPkkfUzRgZw8+AHZxV62TPWhxrZETAuEaahrQ6HViQRAfk60gLvT37iWZrG\n" +
                "BU64272NrJ+UFXrzAEKZ/HK+hIL6yZvYDqIxWBg3Pwt9YxgpOfJ8UeYcrEx3\n" +
                "B1Hkd6QprSOLFCj53zZ++q3SZkWYz28gAA==\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";

    /** Created with gosop 430bb02923c123e39815814f6b97a6d501bdde6a, --profile=rfc9580. */
    private static final String X448_MSG =
        "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wYUGIQaz5Iy7+n5O1bg87Cy2PfSolKK6L8cwIPLJnEeZFjMu2xoAfSM/MwQpXahy\n" +
                "Od1pknhDyw3X5EgxQG0EffQCMpaKsNtqvVGYBJ5chuAcV/8gayReP/g6RREGeyj4\n" +
                "Vc2dgJ67/KwaP0Z7k7vExHs79U24DsrU088QbYhk/XLvJHWlXXj90loCCQMMIvmD\n" +
                "KS5f5WYbntB4N+FspsbQ7GN6taOrAqUtEuKWKzrlhZdtg9qGG4RLCvX1vfL0u6NV\n" +
                "Yzk9fGVgty73B8pmyYdefLdWt87ljwr8wGGX/Dl8PSBIE3w=\n" +
                "-----END PGP MESSAGE-----\n";
}
