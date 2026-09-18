package org.bouncycastle.jsl.test;

import java.security.KeyPairGenerator;

import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jsl.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jsl.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.jsl.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.jsl.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jsl.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.operator.OutputEncryptor;
import org.bouncycastle.jsl.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.jsl.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A PBES2 private key encrypted under a CBC scheme must come out PADDED.
 * <p>
 * The encryption-scheme OID does not tell a JCA provider to pad. RFC 8018 sec. B.2.5 defines the
 * PBES2 AES-CBC scheme with PKCS#5 padding, but providers disagree about whether the algorithm OID
 * used as a transformation name implies it: BouncyCastle pads, while SunJCE and JSL both hand back a
 * raw CBC cipher. Since the OID DOES resolve on JSL, the bare-OID lookup succeeds and the failure
 * lands late, at doFinal, as "data not block size aligned" - so this is caught by inspecting the
 * artefact, not by a missing-algorithm error.
 * <p>
 * {@code JceUtils.createCipher} therefore names the padded transformation for these schemes, the
 * way {@code cms.jcajce.EnvelopedDataHelper} and {@code cert.crmf.jcajce.CRMFHelper} already do in
 * their own layers. This test exists because that fix has no other guard: revert the table and it
 * fails at finalisation with IllegalStateException "cannot encode privateKeyInfo".
 * <p>
 * ENCRYPT ONLY, deliberately. Reading the blob back needs a SecretKeyFactory for the PBKDF2 OID
 * 1.2.840.113549.1.5.12, which JSL does not yet register, so a round-trip test would fail for an
 * unrelated reason. The encrypt half runs on JSL and on both FIPS modules - probed 2026-09-08 - so
 * this needs no capability gate.
 */
public class Pbes2CbcPaddingTest
    extends JostleProviderTestBase
{
    private static final int BLOCK = 16;

    @Test
    public void aes256CbcCiphertextIsPadded()
        throws Exception
    {
        assertPaddedToBlock(NISTObjectIdentifiers.id_aes256_CBC, BLOCK);
    }

    @Test
    public void aes128CbcCiphertextIsPadded()
        throws Exception
    {
        assertPaddedToBlock(NISTObjectIdentifiers.id_aes128_CBC, BLOCK);
    }

    private void assertPaddedToBlock(ASN1ObjectIdentifier scheme, int blockSize)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JslTestProvider.name());
        kpg.initialize(2048);

        PrivateKeyInfo pkInfo =
            PrivateKeyInfo.getInstance(kpg.generateKeyPair().getPrivate().getEncoded());
        int plaintextLen = pkInfo.getEncoded().length;

        OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(scheme)
            .setProvider(JslTestProvider.name())
            .build("hello".toCharArray());

        byte[] encoded = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo).build(encryptor).getEncoded();

        EncryptedPrivateKeyInfo epki = EncryptedPrivateKeyInfo.getInstance(encoded);
        AlgorithmIdentifier outer = epki.getEncryptionAlgorithm();

        assertEquals("outer algorithm should be PBES2",
            PKCSObjectIdentifiers.id_PBES2, outer.getAlgorithm());

        PBES2Parameters pbes2 = PBES2Parameters.getInstance(outer.getParameters());
        assertEquals("encryption scheme should be the one asked for",
            scheme, pbes2.getEncryptionScheme().getAlgorithm());

        int ciphertextLen = epki.getEncryptedData().length;

        // PKCS#5 padding adds 1..blockSize bytes, so the ciphertext is the plaintext rounded UP to
        // the next multiple of the block size - strictly longer, never equal.
        int expected = ((plaintextLen / blockSize) + 1) * blockSize;

        assertEquals("ciphertext should be the plaintext padded to the next block", expected, ciphertextLen);
        assertEquals("ciphertext should be block-aligned", 0, ciphertextLen % blockSize);
        assertTrue("padding must add at least one byte", ciphertextLen > plaintextLen);
    }
}
