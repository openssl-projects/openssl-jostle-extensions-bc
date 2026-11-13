package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jsl.asn1.ASN1Encoding;
import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jsl.asn1.DEROctetString;
import org.bouncycastle.jsl.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jsl.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.test.TestResourceFinder;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.encoders.Hex;
import org.junit.Test;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * The ML-KEM shared secret TLS uses is the one FIPS 203 defines, with no key derivation applied to it.
 * <p>
 * Every TLS handshake test in this module runs this library against itself, so both ends agree
 * whatever they compute: a secret passed through a KDF on both sides still completes the handshake.
 * This checks KemUtil against the NIST ACVP decapsulation vectors, which no part of this library
 * produced. In this package because KemUtil is package-private.
 * </p>
 */
public class KemUtilVectorTest
{
    private static final String[] PARAMETER_SETS = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

    private static final ASN1ObjectIdentifier[] OIDS = { NISTObjectIdentifiers.id_alg_ml_kem_512,
        NISTObjectIdentifiers.id_alg_ml_kem_768, NISTObjectIdentifiers.id_alg_ml_kem_1024 };

    @Test
    public void decapsulationMatchesTheAcvpVectors()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm(
            "KeyGenerator.ML-KEM-512", "KeyGenerator.ML-KEM-768", "KeyGenerator.ML-KEM-1024");

        JcaTlsCrypto crypto = crypto();
        int[] checked = new int[PARAMETER_SETS.length];

        BufferedReader in = new BufferedReader(new InputStreamReader(
            TestResourceFinder.findTestResource("pqc/crypto/mlkem", "ML-KEM-encapDecap.txt"), "UTF-8"));
        try
        {
            String parameterSet = null, function = null, tcId = null;
            byte[] dk = null, c = null;

            for (String line = in.readLine(); line != null; line = in.readLine())
            {
                int eq = line.indexOf(" = ");
                if (eq < 0)
                {
                    continue;
                }

                String name = line.substring(0, eq), value = line.substring(eq + 3).trim();
                if (name.equals("parameterSet"))
                {
                    parameterSet = value;
                }
                else if (name.equals("function"))
                {
                    function = value;
                }
                else if (name.equals("tcId"))
                {
                    tcId = value;
                }
                else if (name.equals("dk"))
                {
                    dk = Hex.decode(value);
                }
                else if (name.equals("c"))
                {
                    c = Hex.decode(value);
                }
                else if (name.equals("k") && "decapsulation".equals(function))
                {
                    String label = parameterSet + " tcId " + tcId;
                    byte[] secret =
                        KemUtil.decapsulate(crypto, parameterSet, privateKey(parameterSet, dk), c).extract();

                    assertEquals(label + ": shared secret length", 32, secret.length);
                    assertTrue(label + ": KemUtil does not return the FIPS 203 shared secret",
                        Arrays.areEqual(Hex.decode(value), secret));

                    checked[indexOf(parameterSet)]++;
                }
            }
        }
        finally
        {
            in.close();
        }

        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            assertTrue("no decapsulation vector was checked for " + PARAMETER_SETS[i], checked[i] > 0);
        }
    }

    /**
     * Encapsulation takes fresh randomness, so it has no known answer. It is tied to the vector-checked
     * decapsulation instead: the secret KemUtil.encapsulate returns must be the one a plain no-KDF
     * decapsulation of its ciphertext gives.
     */
    @Test
    public void encapsulationAgreesWithARawDecapsulation()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm(
            "KeyGenerator.ML-KEM-512", "KeyGenerator.ML-KEM-768", "KeyGenerator.ML-KEM-1024");

        JcaTlsCrypto crypto = crypto();

        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            String parameterSet = PARAMETER_SETS[i];
            KeyPair keyPair = KemUtil.generateKeyPair(crypto, parameterSet);
            PublicKey publicKey = keyPair.getPublic();

            SecretKeyWithEncapsulation encapsulated = KemUtil.encapsulate(crypto, parameterSet, publicKey);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(parameterSet, JslTestProvider.provider());
            keyGenerator.init(KEMExtractSpec.builder()
                .withPrivate(keyPair.getPrivate())
                .withEncapsulatedKey(encapsulated.getEncapsulation())
                .withAlgorithmName("DEF")
                .withKeySizeInBits(256)
                .withNoKdf()
                .build());
            byte[] raw = ((SecretKeyWithEncapsulation)keyGenerator.generateKey()).getEncoded();

            assertTrue(parameterSet + ": the encapsulated secret is not the raw shared secret",
                Arrays.areEqual(raw, encapsulated.getEncoded()));
            assertTrue(parameterSet + ": KemUtil.decapsulate disagrees with KemUtil.encapsulate",
                Arrays.areEqual(raw, KemUtil.decapsulate(crypto, parameterSet, keyPair.getPrivate(),
                    encapsulated.getEncapsulation()).extract()));
        }
    }

    private static JcaTlsCrypto crypto()
    {
        return new JcaTlsCryptoProvider().setProvider(JslTestProvider.install()).create(new SecureRandom());
    }

    private static int indexOf(String parameterSet)
    {
        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            if (PARAMETER_SETS[i].equals(parameterSet))
            {
                return i;
            }
        }
        throw new IllegalArgumentException("unexpected parameter set " + parameterSet);
    }

    /** The decapsulation key as a PKCS#8 key in the expanded-key form: an OCTET STRING holding dk. */
    private static PrivateKey privateKey(String parameterSet, byte[] dk)
        throws Exception
    {
        PrivateKeyInfo info = new PrivateKeyInfo(
            new AlgorithmIdentifier(OIDS[indexOf(parameterSet)]), new DEROctetString(dk));

        return KeyFactory.getInstance(parameterSet, JslTestProvider.provider())
            .generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded(ASN1Encoding.DER)));
    }
}
