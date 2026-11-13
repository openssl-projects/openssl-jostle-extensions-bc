package org.bouncycastle.jsl.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.jsl.bcpg.HashAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyPacket;
import org.bouncycastle.jsl.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataList;
import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPKeyPair;
import org.bouncycastle.jsl.openpgp.PGPLiteralData;
import org.bouncycastle.jsl.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPPrivateKey;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.jsl.openpgp.PGPSignature;
import org.bouncycastle.jsl.openpgp.PGPSignatureGenerator;
import org.bouncycastle.jsl.openpgp.PGPSignatureList;
import org.bouncycastle.jsl.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.jsl.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The RFC 9980 post-quantum OpenPGP algorithms through the JCA operators, on the provider under test.
 * <p>
 * {@code PGPRFC9980VectorTest} reads the RFC's own keys and messages. This covers what the vectors do
 * not: generating each key pair, signing with it and encrypting to it. The component keys come from
 * the provider's own ML-DSA, SLH-DSA and ML-KEM services, and the composite keys are held in this
 * library's {@code CompositePrivateKey} and {@code CompositePublicKey} containers.
 * </p>
 */
public class PgpRfc9980KeyPairTest
{
    private static final byte[] DATA = Strings.toUTF8ByteArray("Hello, post-quantum world!\n");

    @BeforeClass
    public static void installProvider()
    {
        JslTestProvider.install();
    }

    private static PGPKeyPairGenerator generator(int version)
        throws PGPException
    {
        return new JcaPGPKeyPairGeneratorProvider().setProvider(JslTestProvider.provider()).get(version, new Date());
    }

    @Test
    public void anMldsa65Ed25519KeyPairSignsAndVerifies()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.Ed25519");

        implTestSigning(generator(PublicKeyPacket.VERSION_6).generateMLDSA65Ed25519KeyPair(),
            PublicKeyAlgorithmTags.MLDSA65_Ed25519);
    }

    @Test
    public void anMldsa87Ed448KeyPairSignsAndVerifies()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.Ed448");

        implTestSigning(generator(PublicKeyPacket.VERSION_6).generateMLDSA87Ed448KeyPair(),
            PublicKeyAlgorithmTags.MLDSA87_Ed448);
    }

    @Test
    public void everySlhDsaKeyPairSignsAndVerifies()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.SLH-DSA");

        PGPKeyPairGenerator gen = generator(PublicKeyPacket.VERSION_6);

        implTestSigning(gen.generateSLHDSAShake128sKeyPair(), PublicKeyAlgorithmTags.SLHDSA_SHAKE_128s);
        implTestSigning(gen.generateSLHDSAShake128fKeyPair(), PublicKeyAlgorithmTags.SLHDSA_SHAKE_128f);
        implTestSigning(gen.generateSLHDSAShake256sKeyPair(), PublicKeyAlgorithmTags.SLHDSA_SHAKE_256s);
    }

    @Test
    public void anMlkem768X25519KeyPairEncryptsAndDecrypts()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyGenerator.ML-KEM", "KeyAgreement.X25519", "MessageDigest.SHA3-256");

        implTestEncryption(generator(PublicKeyPacket.VERSION_6).generateMLKEM768X25519KeyPair(),
            PublicKeyAlgorithmTags.MLKEM768_X25519);
    }

    @Test
    public void anMlkem1024X448KeyPairEncryptsAndDecrypts()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyGenerator.ML-KEM", "KeyAgreement.X448", "MessageDigest.SHA3-256");

        implTestEncryption(generator(PublicKeyPacket.VERSION_6).generateMLKEM1024X448KeyPair(),
            PublicKeyAlgorithmTags.MLKEM1024_X448);
    }

    /** RFC 9980 sec. 3.5: only ML-KEM-768 + X25519 may sit on a version 4 key. */
    @Test
    public void aVersion4GeneratorRefusesTheVersion6OnlyAlgorithms()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.Ed25519");

        try
        {
            generator(PublicKeyPacket.VERSION_4).generateMLDSA65Ed25519KeyPair();
            fail("a version 4 ML-DSA-65 + Ed25519 key pair was generated");
        }
        catch (PGPException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("RFC 9980 sec. 3.5") >= 0);
        }
    }

    /** RFC 9980 sec. 5.3.1: a digest under 256 bits is refused when signing. */
    @Test
    public void aSmallDigestIsRefusedForACompositeSignature()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Signature.ML-DSA", "Signature.Ed25519");

        PGPKeyPair keyPair = generator(PublicKeyPacket.VERSION_6).generateMLDSA65Ed25519KeyPair();
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.MLDSA65_Ed25519, HashAlgorithmTags.SHA224)
                .setProvider(JslTestProvider.provider()), keyPair.getPublicKey());

        try
        {
            sigGen.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());
            fail("a 224 bit digest was accepted");
        }
        catch (PGPException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("at least 256 bits") >= 0);
        }
    }

    private void implTestSigning(PGPKeyPair keyPair, int algorithm)
        throws Exception
    {
        assertEquals(algorithm, keyPair.getPublicKey().getAlgorithm());
        assertEquals(PublicKeyPacket.VERSION_6, keyPair.getPublicKey().getVersion());

        implTestPrivateKeyRoundTrip(keyPair);

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(algorithm, HashAlgorithmTags.SHA512).setProvider(JslTestProvider.provider()),
            keyPair.getPublicKey());
        sigGen.init(PGPSignature.BINARY_DOCUMENT, keyPair.getPrivateKey());
        sigGen.update(DATA);

        // through the encoding, as a receiver would see it
        PGPSignatureList sigs = (PGPSignatureList)new JcaPGPObjectFactory(sigGen.generate().getEncoded()).nextObject();
        PGPSignature sig = sigs.get(0);
        assertEquals(algorithm, sig.getKeyAlgorithm());

        JcaPGPContentVerifierBuilderProvider verifier =
            new JcaPGPContentVerifierBuilderProvider().setProvider(JslTestProvider.provider());

        sig.init(verifier, keyPair.getPublicKey());
        sig.update(DATA);
        assertTrue("signature by algorithm " + algorithm + " did not verify", sig.verify());

        sig.init(verifier, keyPair.getPublicKey());
        sig.update(Strings.toUTF8ByteArray("Hello, other world!\n"));
        assertFalse("signature by algorithm " + algorithm + " verified over other data", sig.verify());
    }

    private void implTestEncryption(PGPKeyPair keyPair, int algorithm)
        throws Exception
    {
        assertEquals(algorithm, keyPair.getPublicKey().getAlgorithm());
        assertTrue(keyPair.getPublicKey().isEncryptionKey());

        implTestPrivateKeyRoundTrip(keyPair);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setProvider(JslTestProvider.provider()).setWithIntegrityPacket(true));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey())
            .setProvider(JslTestProvider.provider()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream encOut = encGen.open(bOut, new byte[1 << 12]);
        OutputStream litOut = new PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "", DATA.length, new Date());
        litOut.write(DATA);
        litOut.close();
        encOut.close();

        PGPEncryptedDataList encList = (PGPEncryptedDataList)new JcaPGPObjectFactory(bOut.toByteArray()).nextObject();
        assertEquals(1, encList.size());
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)encList.get(0);
        assertEquals(algorithm, encData.getAlgorithm());

        InputStream clear = encData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
            .setProvider(JslTestProvider.provider()).build(keyPair.getPrivateKey()));
        PGPLiteralData lit = (PGPLiteralData)new JcaPGPObjectFactory(clear).nextObject();

        assertTrue("the message did not decrypt to the plaintext",
            Arrays.areEqual(DATA, Streams.readAll(lit.getDataStream())));
        assertTrue("the integrity check failed", encData.verify());
    }

    /** The converter has to turn the PGP private key into provider keys and back to the same packet. */
    private void implTestPrivateKeyRoundTrip(PGPKeyPair keyPair)
        throws Exception
    {
        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(JslTestProvider.provider());
        PGPPrivateKey privateKey = keyPair.getPrivateKey();

        PGPPrivateKey back = converter.getPGPPrivateKey(keyPair.getPublicKey(), converter.getPrivateKey(privateKey));

        assertTrue("the private key packet changed on the way through the converter",
            Arrays.areEqual(privateKey.getPrivateKeyDataPacket().getEncoded(), back.getPrivateKeyDataPacket().getEncoded()));
    }
}
