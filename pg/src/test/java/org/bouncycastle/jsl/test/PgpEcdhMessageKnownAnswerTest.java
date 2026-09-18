package org.bouncycastle.jsl.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.bouncycastle.jsl.gpg.SExprParser;
import org.bouncycastle.jsl.openpgp.PGPCompressedData;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataList;
import org.bouncycastle.jsl.openpgp.PGPLiteralData;
import org.bouncycastle.jsl.openpgp.PGPObjectFactory;
import org.bouncycastle.jsl.openpgp.PGPOnePassSignature;
import org.bouncycastle.jsl.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.jsl.openpgp.PGPPublicKey;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.jsl.openpgp.PGPSecretKey;
import org.bouncycastle.jsl.openpgp.PGPSignatureList;
import org.bouncycastle.jsl.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.jsl.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.jsl.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * RFC 6637 ECDH decryption of fixed GnuPG messages, ported from bc-java's {@code PGPECMessageTest}.
 * <p>
 * Known answers rather than a round trip: the key, the ciphertext and the plaintext file name are
 * all fixed, on NIST P-256 with an SHA-256 CKDF. This is the oracle for the key-agreement path -
 * {@code JcePublicKeyDataDecryptorFactoryBuilder} through Jostle's {@code UserKeyingMaterialSpec} -
 * so a wrong Param block or a dropped UKM fails here rather than passing a self-consistent round
 * trip. The BouncyCastle-operator cells of the upstream class are dropped; this fork has no
 * {@code *.bc.*} operators.
 */
public class PgpEcdhMessageKnownAnswerTest
{
    @BeforeClass
    public static void installProvider()
    {
        JslTestProvider.install();
    }

    private static final byte[] testPubKey =
        Base64.decode(
            "mFIEU5SAxhMIKoZIzj0DAQcCAwRqnFLCB8EEZkAELNqznk8yQau/f1PACUTU/Qe9\n" +
                "jlybc22bO55BdvZdFoa3RmNQHhR980/KeVwCQ3cPpe6OQJFAtD9OSVNUIFAtMjU2\n" +
                "IChHZW5lcmF0ZWQgYnkgR1BHIDIuMSBiZXRhKSA8bmlzdC1wLTI1NkBleGFtcGxl\n" +
                "LmNvbT6IeQQTEwgAIQUCU5SAxgIbAwYLCQgHAwIGFQgCCQoLAxYCAQIeAQIXgAAK\n" +
                "CRA2iYNe+deDntxvAP90U2BUL2YcxrJYnsK783VIPM5U5/2IhH7azbRfaHiLZgEA\n" +
                "1/BVNxRG/Q07gPSdEGagRZcrzPxMQPLjBL4T7Nq5eSG4VgRTlIDqEggqhkjOPQMB\n" +
                "BwIDBJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJkyDTsFNZLIugMLX/zTn3r\n" +
                "rOamvHUdXNbLy1s8PeyrztMcOnwDAQgHiGEEGBMIAAkFAlOUgOoCGwwACgkQNomD\n" +
                "XvnXg556SQD+MCXRkYgLPd0NWWbCKl5wYk4NwWRvOCDFGk7eYoRTKaYBAIkt3J86\n" +
                "Bn0zCzsphjrIUlGPXhLSX/2aJQDuuK3zzLmn");

    private static final byte[] sExprKeySub =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTA6TklT"
             + "VCBQLTI1NikoMTpxNjU6BJlWEj5qR12xbmp5dkjEkV+PRSfk37NKnw8axSJk"
             + "yDTsFNZLIugMLX/zTn3rrOamvHUdXNbLy1s8PeyrztMcOnwpKDk6cHJvdGVj"
             + "dGVkMjU6b3BlbnBncC1zMmszLXNoYTEtYWVzLWNiYygoNDpzaGExODpu2e7w"
             + "pW4L5jg6MTI5MDU0NzIpMTY6ohIkbi1P1O7QX1zgPd7Ejik5NjrCoM9qBxzy"
             + "LVJJMVRGlsjltF9/CeLnRPN1sjeiQrP1vAlZMPiOpYTmGDVRcZhdkCRO06MY"
             + "UTLDZK1wsxELVD0s9irpbskcOnXwqtXbIqhoK4B+9pnkR0h5gi0xPIGSTtYp"
             + "KDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE1MjgxMCkpKQ==");

    private static final byte[] encMessage =
        Base64.decode("hH4DrQCblwYU61MSAgMEVXjgPW2hvIhUMQ2qlAQlAliZKbyujaYfLnwZTeGvu+pt\n"+
            "gJXt+JJ8zWoENxLAp+Nb3PxJW4CjvkXQ2dEmmvkhBzAhDer86XJBrQLBQUL+6EmE\n"+
            "l+/3Yzt+cPEyEn32BSpkt31F2yGncoefCUDgj9tKiFXSRwGhjRno0qzB3CfRWzDu\n"+
            "eelwwtRcxnvXNc44TuHRf4PgZ3d4dDU69bWQswdQ5UTP/Bjjo92yMLtJ3HtBuym+\n"+
            "NazbQUh4M+SP");

    private static final byte[] signedEncMessage =
        Base64.decode("hH4DrQCblwYU61MSAgMEC/jpqjgnqotzKWNWJ3bhOxmmChghrV2PLQbQqtHtVvbj\n" +
            "zyLpaPgeqLslMAjsdy8rlANCjlweZhtP1DmvHiYgjDAA54eptpLMtbULaQOoRcsZ\n" +
            "ZnMqhx9s5phAohNFGC+DnVU/IwxDOnI+ya54LOoXUrrSsgEKDTlAmYr4/oDmLTXt\n" +
            "TaLgk0T9nBxGe8WbLwhPRBIyq6NX151aQ+pOobajrRiLwg/CwUsbAZ50bBPn2JjX\n" +
            "wgBhBjyAn7D6bZ4hMl3YSluSiFkJhxZcYSydtIAlX35q4D/pJjT4mPT/y7ypytCU\n" +
            "0wWo53O6NCSeM/EpeFw8RRh8fe+m33qpA6T5sR3Alg4ZukiIxLa36k6Cv5KTHmB3\n" +
            "6lKZcgQDHNIKStV1bW4Cva1aXXQ=");

    @Test
    public void aFixedEcdhMessageDecryptsToItsKnownFileName()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyAgreement.ECCDHwithSHA256CKDF");

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(encMessage);
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        PGPPublicKey publicKey = new JcaPGPPublicKeyRing(testPubKey).getPublicKey(encP.getKeyID());
        PGPSecretKey secretKey = new SExprParser(null).parseSecretKey(
            new ByteArrayInputStream(sExprKeySub),
            new JcePBEProtectionRemoverFactory("test".toCharArray()).setProvider(JslTestProvider.name()),
            publicKey);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(JslTestProvider.name())
            .build(secretKey.extractPrivateKey(null)));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();
        PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());

        PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();
        assertEquals("wrong file name recovered", "test.txt", lData.getFileName());
    }

    @Test
    public void aFixedSignedEcdhMessageDecryptsAndItsSignatureVerifies()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyAgreement.ECCDHwithSHA256CKDF");
        JslTestProvider.assumeAlgorithm("Signature.SHA256withECDSA");

        PGPObjectFactory pgpFact = new JcaPGPObjectFactory(signedEncMessage);
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpFact.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        JcaPGPPublicKeyRing publicKeyRing = new JcaPGPPublicKeyRing(testPubKey);
        PGPPublicKey publicKey = publicKeyRing.getPublicKey(encP.getKeyID());

        SExprParser sExprParser = new SExprParser(
            new JcaPGPDigestCalculatorProviderBuilder().setProvider(JslTestProvider.name()).build());
        PGPSecretKey secretKey = sExprParser.parseSecretKey(
            new ByteArrayInputStream(sExprKeySub),
            new JcePBEProtectionRemoverFactory("test".toCharArray()).setProvider(JslTestProvider.name()),
            publicKey);

        InputStream clear = encP.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(JslTestProvider.name())
            .build(secretKey.extractPrivateKey(null)));

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();
        PGPObjectFactory compFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());

        PGPOnePassSignatureList sList = (PGPOnePassSignatureList)compFact.nextObject();
        PGPOnePassSignature ops = sList.get(0);

        PGPLiteralData lData = (PGPLiteralData)compFact.nextObject();
        assertEquals("wrong file name recovered", "test.txt", lData.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(JslTestProvider.name()),
            publicKeyRing.getPublicKey(ops.getKeyID()));

        InputStream dIn = lData.getInputStream();
        int ch;
        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignatureList p3 = (PGPSignatureList)compFact.nextObject();
        assertTrue("the one-pass signature did not verify", ops.verify(p3.get(0)));
    }
}
