package org.bouncycastle.jsl.test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Pins that a caller-supplied SecureRandom determines the content-encryption IV.
 * <p>
 * This passes today, and the reason it passes is an accident worth pinning. EnvelopedDataHelper's
 * {@code generateParameters} only calls {@code pGen.init(..., rand)} on the RC2_CBC branch; every
 * other algorithm falls through to a bare {@code pGen.generateParameters()}, which would use the
 * provider's own SecureRandom and ignore the caller's. That branch is UNREACHABLE on JSL: the
 * provider serves exactly two AlgorithmParameterGenerator algorithms, DH and DSA, so
 * {@code createAlgorithmParameterGenerator} throws NoSuchAlgorithmException for AES,
 * {@code generateParameters} returns null, and JceCMSContentEncryptorBuilder falls to its
 * "second guess" path, which inits the Cipher with the caller's random and reads the IV back off
 * it. Measured, not read: the earlier claim that this was a live bug here was wrong.
 * <p>
 * So this is a regression pin against a PROVIDER change, not against our own code. The day jostle
 * adds an AES AlgorithmParameterGenerator, {@code generateParameters} starts returning non-null,
 * the un-inited pGen path becomes live, and the caller's random is silently dropped. This test
 * fails on that day, which is the point of it.
 * <p>
 * The recipient is an AES KEKRecipientInfo, not RSA key transport. That is deliberate: this test
 * is about the CONTENT encryptor's IV, and RSA PKCS#1 v1.5 key transport is refused by both FIPS
 * modules, so a key-transport fixture would have forced a gate and lost two thirds of the coverage
 * for a reason having nothing to do with what is under test. Measured the hard way - the first
 * version of this test used key transport, passed on JSL and failed on both FIPS legs with
 * "padding PKCS1Padding not supported".
 * <p>
 * The assertion is the PROPERTY, not specific bytes: two runs with equal fixed randoms must produce
 * the same IV, and a different fixed random must produce a different one. That holds whatever order
 * the CEK and the IV draw their bytes in, which specific-byte assertions do not - and the byte
 * budget is deliberately generous, because a fixture sized to BC's draw is exactly what ran short
 * against OpenSSL's in ETSIEncryptedDataTest.
 */public class ContentEncryptorRandomTest
{
    private static byte[] fixedBytes(byte fill)
    {
        byte[] b = new byte[512];
        Arrays.fill(b, fill);
        return b;
    }

    @Test
    public void testCallerSecureRandomDeterminesTheIv()
        throws Exception
    {
        JslTestProvider.install();

        byte[] ivA1 = ivFor(fixedBytes((byte)0x11));
        byte[] ivA2 = ivFor(fixedBytes((byte)0x11));
        byte[] ivB = ivFor(fixedBytes((byte)0x22));

        assertNotNull("no content-encryption parameters were produced", ivA1);
        assertTrue("equal caller randoms must give the same IV, was "
            + Hex.toHexString(ivA1) + " then " + Hex.toHexString(ivA2),
            Arrays.areEqual(ivA1, ivA2));
        assertFalse("a different caller random must give a different IV",
            Arrays.areEqual(ivA1, ivB));
    }

    private static byte[] ivFor(byte[] randomBytes)
        throws Exception
    {
        SecretKey kek = new SecretKeySpec(new byte[32], "AES");

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(
            new JceKEKRecipientInfoGenerator(new byte[]{ 1, 2, 3, 4, 5 }, kek)
                .setProvider(JslTestProvider.name()));

        CMSEnvelopedData ed = edGen.generate(
            new CMSProcessableByteArray("WallaWallaWashington".getBytes()),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                .setProvider(JslTestProvider.name())
                .setSecureRandom(new FixedSecureRandom(randomBytes))
                .build());

        return ASN1OctetString.getInstance(
            ed.getContentEncryptionAlgorithm().getParameters()).getOctets();
    }
}
