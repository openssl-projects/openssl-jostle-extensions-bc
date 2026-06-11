package org.bouncycastle.jsl.test;

import java.security.AlgorithmParameters;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Symmetric pillar: AES-256-GCM encrypt/decrypt delegated to OpenSSL through JSL,
 * including an AEAD tamper check.
 */
public class AesGcmTest
    extends JostleProviderTestBase
{
    @Test
    public void aes256GcmRoundTripAndTamper()
        throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(256);
        SecretKey key = kg.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        byte[] pt = "symmetric through OpenSSL".getBytes("UTF-8");

        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = enc.doFinal(pt);

        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        assertTrue("AES-256-GCM did not round-trip", Arrays.areEqual(pt, dec.doFinal(ct)));

        // flip a ciphertext byte -> GCM tag must reject
        ct[0] ^= 0x01;
        Cipher bad = Cipher.getInstance("AES/GCM/NoPadding", JSL);
        bad.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        boolean rejected = false;
        try
        {
            bad.doFinal(ct);
        }
        catch (Exception e)
        {
            rejected = true;
        }
        assertTrue("tampered AES-GCM ciphertext was not rejected", rejected);
    }

    /**
     * The behaviour CMS depends on: initialise an AES-GCM cipher (resolved by its
     * NIST OID) for encryption WITHOUT supplying parameters, and the provider must
     * auto-generate the IV and expose it via getParameters() so the recipient can
     * decrypt. Previously engineGetParameters() threw "not implemented".
     */
    @Test
    public void gcmAutoGeneratesIvAndExposesParameters()
        throws Exception
    {
        final String AES256_GCM_OID = "2.16.840.1.101.3.4.1.46";

        KeyGenerator kg = KeyGenerator.getInstance(AES256_GCM_OID, JSL);
        kg.init(256);
        SecretKey key = kg.generateKey();

        Cipher enc = Cipher.getInstance(AES256_GCM_OID, JSL);
        enc.init(Cipher.ENCRYPT_MODE, key);             // no params supplied
        byte[] pt = "cms-style content encryption".getBytes("UTF-8");
        byte[] ct = enc.doFinal(pt);

        AlgorithmParameters params = enc.getParameters();
        assertNotNull("GCM cipher did not expose auto-generated parameters", params);
        assertEquals("expected a 12-byte auto-generated GCM nonce", 12, enc.getIV().length);

        Cipher dec = Cipher.getInstance(AES256_GCM_OID, JSL);
        dec.init(Cipher.DECRYPT_MODE, key, params);     // decrypt using recovered params
        assertTrue("round-trip via getParameters() failed", Arrays.areEqual(pt, dec.doFinal(ct)));
    }
}
