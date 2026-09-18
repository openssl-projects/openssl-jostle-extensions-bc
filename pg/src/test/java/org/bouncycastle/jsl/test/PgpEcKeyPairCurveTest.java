package org.bouncycastle.jsl.test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPairGeneratorProvider;
import org.bouncycastle.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Classic EC key pairs for OpenPGP on JSL, generated and converted back.
 * <p>
 * JSL serves one EC generator and one EC key factory, both named {@code EC}, and takes the curve as
 * an OID through {@code ECGenParameterSpec}; there is no {@code ECDH} or {@code ECDSA} service to
 * ask for. Generation alone is not enough to call the curve usable - the converter has to turn the
 * PGP key back into a JCA key pair - so each curve is asserted both ways.
 */
public class PgpEcKeyPairCurveTest
{
    /** The curves RFC 6637 names, plus the brainpool ones RFC 9580 adds. */
    private static final ASN1ObjectIdentifier[] CURVES = new ASN1ObjectIdentifier[]{
        X9ObjectIdentifiers.prime256v1,
        SECObjectIdentifiers.secp384r1,
        SECObjectIdentifiers.secp521r1,
        TeleTrusTObjectIdentifiers.brainpoolP256r1,
        TeleTrusTObjectIdentifiers.brainpoolP384r1,
        TeleTrusTObjectIdentifiers.brainpoolP512r1};

    @BeforeClass
    public static void installProvider()
    {
        JslTestProvider.install();
    }

    @Test
    public void everyNamedCurveGeneratesAnEcdhKeyPairThatConvertsBack()
        throws Exception
    {
        for (ASN1ObjectIdentifier curve : CURVES)
        {
            implTestCurve(curve, PublicKeyAlgorithmTags.ECDH);
        }
    }

    @Test
    public void everyNamedCurveGeneratesAnEcdsaKeyPairThatConvertsBack()
        throws Exception
    {
        for (ASN1ObjectIdentifier curve : CURVES)
        {
            implTestCurve(curve, PublicKeyAlgorithmTags.ECDSA);
        }
    }

    private void implTestCurve(ASN1ObjectIdentifier curve, int algorithmTag)
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.EC");

        PGPKeyPairGenerator gen = new JcaPGPKeyPairGeneratorProvider()
            .setProvider(JslTestProvider.name())
            .get(PublicKeyPacket.VERSION_4, new Date());

        PGPKeyPair pair = algorithmTag == PublicKeyAlgorithmTags.ECDH
            ? gen.generateECDHKeyPair(curve)
            : gen.generateECDSAKeyPair(curve);

        String what = curve.getId() + "/" + (algorithmTag == PublicKeyAlgorithmTags.ECDH ? "ECDH" : "ECDSA");
        assertNotNull(what + ": no key pair", pair);
        assertEquals(what + ": wrong public-key algorithm tag",
            algorithmTag, pair.getPublicKey().getAlgorithm());

        JcaPGPKeyConverter converter = new JcaPGPKeyConverter().setProvider(JslTestProvider.name());

        PublicKey pub = converter.getPublicKey(pair.getPublicKey());
        assertNotNull(what + ": the public key did not convert back", pub);
        assertEquals(what + ": wrong key algorithm", "EC", pub.getAlgorithm());

        PrivateKey priv = converter.getPrivateKey(pair.getPrivateKey());
        assertNotNull(what + ": the private key did not convert back", priv);

        // The round trip has to reproduce the same public point, not merely produce some key.
        PGPKeyPair again = new org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair(
            PublicKeyPacket.VERSION_4, algorithmTag,
            new java.security.KeyPair(pub, priv), new Date());
        assertTrue(what + ": the converted key is not the one generated",
            Arrays.areEqual(pair.getPublicKey().getPublicKeyPacket().getKey().getEncoded(),
                again.getPublicKey().getPublicKeyPacket().getKey().getEncoded()));
    }
}
