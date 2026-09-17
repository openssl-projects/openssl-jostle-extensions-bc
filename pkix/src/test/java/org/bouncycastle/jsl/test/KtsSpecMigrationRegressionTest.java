package org.bouncycastle.jsl.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.GenericHybridParameters;
import org.bouncycastle.asn1.cms.RsaKemParameters;
import org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JceGenericKey;
import org.bouncycastle.operator.jcajce.JceKTSKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceKTSKeyWrapper;
import org.junit.Before;
import org.junit.Test;
import org.openssl.jostle.jcajce.spec.KTSParameterSpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Guards the KTS migration. The CMS KEM wrappers and the operator KTS pair build JSL's
 * KTSParameterSpec, which takes the KDF as DER rather than as an AlgorithmIdentifier.
 * <p>
 * The CMS round trips live in NewEnvelopedDataTest and MLKEMEnvelopedDataTest. The operator
 * pair had no test at all before this one.
 */
public class KtsSpecMigrationRegressionTest
    extends JostleProviderTestBase
{
    private static final int KEK_BITS = 256;

    @Before
    public void gateOnProviderCapability()
    {
        JslTestProvider.assumeAlgorithm("Cipher.RSA-KTS-KEM-KWS");
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.RSA");
    }

    @Test
    public void operatorKtsPairRoundTrips()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator kg = KeyGenerator.getInstance("AES", JSL);
        kg.init(KEK_BITS);
        SecretKey contentKey = kg.generateKey();

        JceKTSKeyWrapper wrapper = new JceKTSKeyWrapper(
            kp.getPublic(), "AES", KEK_BITS, PARTY_U, PARTY_V).setProvider(JSL);

        byte[] wrapped = wrapper.generateWrappedKey(
            new JceGenericKey(wrapper.getAlgorithmIdentifier(), contentKey));

        GenericKey recovered = new JceKTSKeyUnwrapper(
            wrapper.getAlgorithmIdentifier(), kp.getPrivate(), PARTY_U, PARTY_V)
            .setProvider(JSL)
            .generateUnwrappedKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_CBC), wrapped);

        assertArrayEquals("operator KTS did not round-trip the content key",
            contentKey.getEncoded(), (byte[])recovered.getRepresentation());
    }

    /**
     * The DER JSL is handed is the DER the message carries, NULL digest parameters included.
     * The builder OID-pair convenience takes JSL OID objects, not BC ones, and emits no digest
     * parameters, so every call site passes getEncoded(DER) instead.
     */
    @Test
    public void kdfDerIsByteEqualToTheAlgorithmIdentifierEncoding()
        throws Exception
    {
        AlgorithmIdentifier withNullParams = new AlgorithmIdentifier(
            X9ObjectIdentifiers.id_kdf_kdf3,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));
        byte[] encoded = withNullParams.getEncoded(ASN1Encoding.DER);

        assertArrayEquals("the spec must carry the message's own KDF bytes",
            encoded,
            new KTSParameterSpec.Builder("AES", KEK_BITS)
                .withKdfAlgorithm(encoded).build().getKdfAlgorithm());

        // The operator wrapper names no KDF and takes the builder's default; the unwrapper reads
        // the same identifier off the wire. Both must reach JSL as the same bytes.
        assertArrayEquals("the builder default must equal the KDF the operator pair puts on the wire",
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)).getEncoded(ASN1Encoding.DER),
            new KTSParameterSpec.Builder("AES", KEK_BITS).build().getKdfAlgorithm());
    }

    /**
     * The unwrapper feeds JSL a KDF identifier taken from the message, so the spec's ceiling on
     * that field is load-bearing: an unbounded one would size an allocation from attacker input.
     * A refusal must still surface as the OperatorException the caller is declared to catch.
     */
    @Test
    public void oversizedKdfFromTheMessageIsRefusedAsAnOperatorException()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        AlgorithmIdentifier oversizedKdf = new AlgorithmIdentifier(
            X9ObjectIdentifiers.id_kdf_kdf3, new DEROctetString(new byte[512]));

        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_rsa_KEM,
            new GenericHybridParameters(
                new AlgorithmIdentifier(ISOIECObjectIdentifiers.id_kem_rsa,
                    new RsaKemParameters(oversizedKdf, KEK_BITS / 8)),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap)));

        try
        {
            new JceKTSKeyUnwrapper(algorithm, kp.getPrivate(), PARTY_U, PARTY_V)
                .setProvider(JSL)
                .generateUnwrappedKey(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_CBC),
                    new byte[256 + 40]);
            fail("an oversized KDF identifier was accepted");
        }
        catch (OperatorException e)
        {
            assertEquals(OperatorException.class, e.getClass());
            // Pin the ceiling itself: an ordinary unwrap failure reaches the caller as the same
            // outer type, so only the cause separates the two.
            assertEquals(IllegalArgumentException.class, e.getCause().getClass());
            assertTrue("refusal did not name the ceiling: " + e.getCause().getMessage(),
                e.getCause().getMessage().contains("KDF AlgorithmIdentifier exceeds 256 bytes"));
        }
    }

    private static final byte[] PARTY_U = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
    private static final byte[] PARTY_V = new byte[]{9, 10, 11, 12, 13, 14, 15, 16};
}
