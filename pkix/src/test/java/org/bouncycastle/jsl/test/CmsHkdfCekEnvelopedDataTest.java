package org.bouncycastle.jsl.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.junit.Test;
import org.openssl.jostle.jcajce.spec.HKDFParameterSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * CMS EnvelopedData with the RFC 9629 {@code id-alg-cek-hkdf-sha256} content-encryption-key
 * derivation enabled ({@link JceCMSContentEncryptorBuilder#setEnableSha256HKdf}). The HKDF-SHA256
 * step runs through JSL's native {@code SecretKeyFactory("HKDF-SHA256")} on both sides -
 * {@code applyKdf} on generation and {@code EnvelopedDataHelper}'s {@code id-alg-cek-hkdf-sha256}
 * branch on recovery - so a round trip proves the two agree.
 * <p>
 * {@code id-alg-cek-hkdf-sha256} is the only CEK HKDF identifier this fork emits
 * ({@code CMSObjectIdentifiers.id_alg_cek_hkdf_sha256}); what varies is the content-encryption
 * algorithm, which supplies both the HKDF {@code info} and the derived key's length.
 */
public class CmsHkdfCekEnvelopedDataTest
    extends JostleProviderTestBase
{
    /** SHA-256 HashLen, for the RFC 5869 sec. 2.3 ceiling of 255 * HashLen octets. */
    private static final int HASH_LEN = 32;

    @Test
    public void hkdfCekRoundTripsForEveryContentKeyLength()
        throws Exception
    {
        roundTrip(CMSAlgorithm.AES128_GCM);
        roundTrip(CMSAlgorithm.AES192_GCM);
        roundTrip(CMSAlgorithm.AES256_GCM);
    }

    /**
     * The derived length is the content key's own length, so it is bounded by the content
     * algorithm rather than by anything on the wire. This states the ceiling the factory itself
     * enforces: a non-positive length would mint an empty key, and RFC 5869 sec. 2.3 caps the
     * output at 255 * HashLen octets.
     */
    @Test
    public void hkdfOutputLengthIsBounded()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("SecretKeyFactory.HKDF-SHA256");

        SecretKeyFactory hkdf = SecretKeyFactory.getInstance("HKDF-SHA256", JSL);
        byte[] ikm = Strings.toByteArray("input keying material");
        byte[] info = Strings.toByteArray("info");

        assertEquals("a valid request must yield exactly the octets asked for", 32,
            hkdf.generateSecret(new HKDFParameterSpec(ikm, null, info, 32)).getEncoded().length);

        refuse(hkdf, ikm, info, 0);
        refuse(hkdf, ikm, info, 255 * HASH_LEN + 1);
    }

    private void refuse(SecretKeyFactory hkdf, byte[] ikm, byte[] info, int outputLength)
        throws Exception
    {
        try
        {
            hkdf.generateSecret(new HKDFParameterSpec(ikm, null, info, outputLength));
            fail("output length " + outputLength + " was accepted");
        }
        catch (InvalidKeySpecException e)
        {
            // the type javax.crypto.SecretKeyFactory declares for a spec it will not derive from
        }
    }

    private void roundTrip(ASN1ObjectIdentifier contentAlgorithm)
        throws Exception
    {
        // RSA-OAEP key transport, not a KEM: the CEK derivation does not depend on the recipient
        // type, and a KEM recipient would gate this away on a module that serves no ML-KEM.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JSL);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        byte[] keyId = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        byte[] data = Strings.toByteArray("envelope me with an HKDF-derived CEK");

        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(
            new JceKeyTransRecipientInfoGenerator(keyId,
                new JcaAlgorithmParametersConverter().getAlgorithmIdentifier(
                    PKCSObjectIdentifiers.id_RSAES_OAEP, OAEPParameterSpec.DEFAULT),
                kp.getPublic()).setProvider(JSL));

        CMSEnvelopedData enveloped = gen.generate(
            new CMSProcessableByteArray(data),
            new JceCMSContentEncryptorBuilder(contentAlgorithm)
                .setEnableSha256HKdf(true)
                .setProvider(JSL)
                .build());

        CMSEnvelopedData parsed = new CMSEnvelopedData(enveloped.getEncoded());
        assertEquals(contentAlgorithm + ": the KDF was not declared on the wire",
            CMSObjectIdentifiers.id_alg_cek_hkdf_sha256.getId(), parsed.getEncryptionAlgOID());

        boolean any = false;
        for (Object o : parsed.getRecipientInfos().getRecipients())
        {
            RecipientInformation ri = (RecipientInformation)o;
            byte[] recovered = ri.getContent(new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(JSL));
            assertTrue(contentAlgorithm + ": HKDF-CEK content did not round-trip",
                Arrays.areEqual(data, recovered));
            any = true;
        }
        assertTrue(contentAlgorithm + ": no recipients present", any);
    }
}
