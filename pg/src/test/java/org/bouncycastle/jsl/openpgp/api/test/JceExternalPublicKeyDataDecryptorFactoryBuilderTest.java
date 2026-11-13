package org.bouncycastle.jsl.openpgp.api.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jsl.bcpg.AEADAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.jsl.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataList;
import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPKeyPair;
import org.bouncycastle.jsl.openpgp.PGPLiteralData;
import org.bouncycastle.jsl.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPPublicKey;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.api.operator.jcajce.JceExternalPublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.jsl.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.jsl.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;
import org.bouncycastle.jsl.util.test.SimpleTest;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Tests for {@link JceExternalPublicKeyDataDecryptorFactoryBuilder}, emulating the externally-held
 * key with a callback that performs the raw private-key operation through the JCA in software.
 */
public class JceExternalPublicKeyDataDecryptorFactoryBuilderTest
    extends SimpleTest
{
    @org.junit.Test
    public void test()
        throws Exception
    {
        org.bouncycastle.jsl.util.test.TestResult result = perform();
        if (!result.isSuccessful())
        {
            throw new junit.framework.AssertionFailedError(result.toString());
        }
    }

    private static final byte[] TEXT = Strings.toByteArray("hello world!\n");

    @Override
    public String getName()
    {
        return "JceExternalPublicKeyDataDecryptorFactoryBuilderTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        // a FIPS module may serve none of these, or only some
        if (!JslTestProvider.supports("KeyAgreement.X25519", "KeyAgreement.X448") || !JslTestProvider.canGetCipher("AES/OCB/NoPadding"))
        {
            return;
        }

        testDedicatedX25519();
        testDedicatedX448();
        testLegacyX25519();
        testNistCurveECDH();
        testRSA();
        testMalformedEncSessionKeyThrowsPGPException();
    }

    /**
     * Builder whose callback holds the private key in software and performs the raw operation the
     * way a hardware token would - taking the ephemeral key as a JCA {@link PublicKey} and returning
     * the plain RSA decryption result / agreement secret.
     */
    private static final class TestExternalBuilder
        extends JceExternalPublicKeyDataDecryptorFactoryBuilder
    {
        private final PrivateKey externalKey;

        TestExternalBuilder(PrivateKey externalKey)
        {
            this.externalKey = externalKey;
        }

        @Override
        public PublicKeyDataDecryptorFactory build(OpenPGPKey.OpenPGPSecretKey secretKey)
            throws PGPException
        {
            throw new UnsupportedOperationException("not used by this test");
        }

        PublicKeyDataDecryptorFactory build(PGPPublicKey pubKey)
            throws PGPException
        {
            return build(new PGPKeyPair(pubKey, null), new PublicKeyCryptoCallback()
            {
                @Override
                public byte[] decrypt(int keyAlgorithm, byte[][] pEnc)
                    throws PGPException
                {
                    Cipher c;
                    try
                    {
                        switch (keyAlgorithm)
                        {
                            case PublicKeyAlgorithmTags.RSA_GENERAL:
                            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                                c = Cipher.getInstance("RSA/ECB/PKCS1Padding", JslTestProvider.name());
                                break;

                                case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                                case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                                    throw new PGPException("ElGamal not supported by the external key");
                            default:
                                throw new PGPException("Unsupported key algorithm: " + keyAlgorithm);
                        }

                        c.init(Cipher.DECRYPT_MODE, externalKey);
                        return c.doFinal(pEnc[0]);
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("external RSA operation failed: " + e.getMessage(), e);
                    }
                }

                @Override
                public byte[] decrypt(int keyAlgorithm, PublicKey ephemeralKey)
                    throws PGPException
                {
                    switch (keyAlgorithm)
                    {
                        case PublicKeyAlgorithmTags.ECDH:
                            return agree("ECDH", ephemeralKey);

                        case PublicKeyAlgorithmTags.X25519:
                            return agree("X25519", ephemeralKey);

                        case PublicKeyAlgorithmTags.X448:
                            return agree("X448", ephemeralKey);

                        default:
                            throw new PGPException("Unsupported key algorithm: " + keyAlgorithm);
                    }
                }

                private byte[] agree(String algorithm, PublicKey ephemeralKey)
                    throws PGPException
                {
                    try
                    {
                        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, JslTestProvider.name());
                        agreement.init(externalKey);
                        agreement.doPhase(ephemeralKey, true);
                        return agreement.generateSecret();
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("external key agreement failed: " + e.getMessage(), e);
                    }
                }
            });
        }
    }

    private void testDedicatedX25519()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519", JslTestProvider.name());
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("dedicated X25519",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, new Date()), kp.getPrivate());
    }

    private void testDedicatedX448()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X448", JslTestProvider.name());
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("dedicated X448",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.X448, kp, new Date()), kp.getPrivate());
    }

    private void testLegacyX25519()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519", JslTestProvider.name());
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("legacy X25519 ECDH",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, new Date()), kp.getPrivate());
    }

    private void testNistCurveECDH()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", JslTestProvider.name());
        gen.initialize(new ECGenParameterSpec("P-256"));
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("P-256 ECDH",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, kp, new Date()), kp.getPrivate());
    }

    private void testRSA()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", JslTestProvider.name());
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        encryptDecryptRoundTrip("RSA",
            new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, new Date()), kp.getPrivate());
    }

    /**
     * A malformed (truncated or length-corrupted) encrypted session key must surface as the
     * {@link PGPException} the interface contract names, exactly as the software-backed factories
     * behave - never as an ArrayIndexOutOfBoundsException or other unchecked exception.
     */
    private void testMalformedEncSessionKeyThrowsPGPException()
        throws Exception
    {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("X25519", JslTestProvider.name());
        KeyPair kp = gen.generateKeyPair();
        PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.X25519, kp, new Date());

        TestExternalBuilder builder = new TestExternalBuilder(kp.getPrivate());
        builder.setProvider(JslTestProvider.provider());
        PublicKeyDataDecryptorFactory factory = builder.build(keyPair.getPublicKey());

        // X25519 ESK truncated right after the ephemeral key: no size octet to read
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.X25519, new byte[32]);

        // v3 X25519 ESK whose size octet (0) leaves no room for the symmetric algorithm id
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.X25519, new byte[33]);

        // ECDH ESK shorter than its own two length octets
        expectMalformedFailure(factory, PublicKeyAlgorithmTags.ECDH, new byte[1]);
    }

    private void expectMalformedFailure(PublicKeyDataDecryptorFactory factory, int keyAlgorithm, byte[] enc)
    {
        try
        {
            factory.recoverSessionData(keyAlgorithm, new byte[][] { enc }, PublicKeyEncSessionPacket.VERSION_3);
            fail("no exception for malformed encrypted session key");
        }
        catch (PGPException e)
        {
            isEquals("encoded length out of range", e.getMessage());
        }
    }

    private void encryptDecryptRoundTrip(String description, PGPKeyPair keyPair, PrivateKey externalKey)
        throws Exception
    {
        // v4 SEIPD with a v3 PKESK, and v6 SEIPD with a v6 PKESK - the two exercise different
        // ESK parsing and data-decryptor paths in the factory
        encryptDecryptRoundTrip(description + " (v4)", keyPair, externalKey,
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
                .setProvider(JslTestProvider.name()).setSecureRandom(new SecureRandom()));
        encryptDecryptRoundTrip(description + " (v6)", keyPair, externalKey,
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setUseV6AEAD().setWithAEAD(AEADAlgorithmTags.OCB, 6)
                .setProvider(JslTestProvider.name()).setSecureRandom(new SecureRandom()));
    }

    private void encryptDecryptRoundTrip(String description, PGPKeyPair keyPair, PrivateKey externalKey,
        JcePGPDataEncryptorBuilder encryptorBuilder)
        throws Exception
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayOutputStream ldOut = new ByteArrayOutputStream();
        OutputStream pOut = lData.open(ldOut, PGPLiteralDataGenerator.UTF8, PGPLiteralData.CONSOLE, TEXT.length, new Date());
        pOut.write(TEXT);
        pOut.close();

        byte[] data = ldOut.toByteArray();

        ByteArrayOutputStream cbOut = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(encryptorBuilder);

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey()).setProvider(JslTestProvider.name()));

        OutputStream cOut = cPk.open(cbOut, data.length);
        cOut.write(data);
        cOut.close();

        // decrypt with a factory that only sees the public half - the raw private-key operation is
        // routed out through the test callback the way a hardware token's would be
        TestExternalBuilder builder = new TestExternalBuilder(externalKey);
        builder.setProvider(JslTestProvider.provider());
        PublicKeyDataDecryptorFactory factory = builder.build(keyPair.getPublicKey());

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cbOut.toByteArray());
        PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();
        PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

        InputStream clear = encP.getDataStream(factory);

        pgpF = new JcaPGPObjectFactory(clear);
        PGPLiteralData ld = (PGPLiteralData)pgpF.nextObject();

        byte[] out = Streams.readAll(ld.getInputStream());

        isTrue(description + ": wrong plain text in decrypted packet", areEqual(out, TEXT));
    }

    public static void main(String[] args)
    {
        JslTestProvider.install();

        runTest(new JceExternalPublicKeyDataDecryptorFactoryBuilderTest());
    }
}
