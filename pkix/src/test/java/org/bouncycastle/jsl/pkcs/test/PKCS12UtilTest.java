package org.bouncycastle.jsl.pkcs.test;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Mac;

import junit.framework.TestCase;
import org.bouncycastle.jsl.asn1.DEROctetString;
import org.bouncycastle.jsl.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.jsl.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.jsl.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jsl.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.cms.CMSAlgorithm;
import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.operator.MacCalculator;
import org.bouncycastle.jsl.operator.OperatorCreationException;
import org.bouncycastle.jsl.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.jsl.pkcs.PKCS12PfxPdu;
import org.bouncycastle.jsl.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.jsl.pkcs.PKCS12SafeBag;
import org.bouncycastle.jsl.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.jsl.pkcs.PKCS12SecretBag;
import org.bouncycastle.jsl.pkcs.PKCS12SecretBagBuilder;
import org.bouncycastle.jsl.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.jsl.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.jsl.pkcs.jcajce.JcePKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.jsl.pkcs.util.PKCS12Util;
import org.bouncycastle.jsl.util.Strings;

/**
 * Ported from bc-java with the MAC scaffolding moved off the absent {@code pkcs.bc} builders onto
 * the Jce ones; the assertions are upstream's.
 */
public class PKCS12UtilTest
    extends TestCase
{
    private static final char[] passwd = "secret".toCharArray();

    public void setUp()
    {
        JslTestProvider.install();
    }

    /*
     * Per-test capability gate. The legacy PKCS#12 MAC registers the Mac under the DIGEST OID
     * (JcePKCS12MacCalculatorBuilder calls createMac(algorithm.getId())), and JSL registers no Mac
     * under one: its PKCS#12 support is KeyStore.PKCS12* only, PBMAC1 included. Nothing about the
     * digest choice fixes it - SHA-1 and SHA-256 fail alike.
     */
    private boolean requirePkcs12PbeMac()
    {
        try
        {
            Mac.getInstance(NISTObjectIdentifiers.id_sha256.getId(), JslTestProvider.name());
            return true;
        }
        catch (Exception e)
        {
            System.out.println("[skipped] " + getName() + ": " + JslTestProvider.name()
                + " registers no Mac under a digest OID, so the legacy PKCS#12 PBE MAC is unavailable");
            return false;
        }
    }

    public void testConvertToDefiniteLength_PBE_RoundTrips()
        throws Exception
    {
        if (!requirePkcs12PbeMac())
        {
            return;
        }

        byte[] pfxBytes = buildPfx(pkcs12Mac()).getEncoded();

        byte[] derBytes = PKCS12Util.convertToDefiniteLength(pfxBytes, passwd, JslTestProvider.name());

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider(JslTestProvider.name()), passwd));
    }

    public void testConvertToDefiniteLength_PBMAC1_RoundTrips()
        throws Exception
    {
        byte[] pfxBytes = buildPfx(pbMac1()).getEncoded();

        byte[] derBytes = PKCS12Util.convertToDefiniteLength(pfxBytes, passwd, JslTestProvider.name());

        PKCS12PfxPdu pfx = new PKCS12PfxPdu(derBytes);
        assertTrue(pfx.hasMac());
        assertTrue(pfx.isMacValid(
            new JcePKCS12MacCalculatorBuilderProvider().setProvider(JslTestProvider.name()), passwd));
    }

    public void testConvertToDefiniteLength_Idempotent()
        throws Exception
    {
        if (!requirePkcs12PbeMac())
        {
            return;
        }

        byte[] pfxBytes = buildPfx(pkcs12Mac()).getEncoded();

        byte[] once = PKCS12Util.convertToDefiniteLength(pfxBytes, passwd, JslTestProvider.name());
        byte[] twice = PKCS12Util.convertToDefiniteLength(once, passwd, JslTestProvider.name());

        assertTrue(Arrays.equals(once, twice));
    }

    /**
     * RFC 9579 sec. 9 (RFC-9579.txt:212-213): "It's RECOMMENDED to reject any KDF parameters that
     * specify key lengths less than 20 octets." The floor belongs to validateMacKeyLength alone -
     * validateKeyLength also bounds the PBES2 content-encryption keyLength reached from
     * PKCS12KeyStoreSpi.wrapKey, where 16 octets is AES-128 and BC writes it into every
     * PKCS12-AES256-AES128 file it produces.
     */
    public void testValidateMacKeyLengthBounds()
    {
        try
        {
            PKCS12Util.validateMacKeyLength(BigInteger.valueOf(8));
            fail("short MAC keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength 8 less than 20", e.getMessage());
        }

        // the upper bound is unchanged, and stays well above the HMAC output size: BC's
        // PKCS12-PBMAC1 keystore asked for a 256-octet MAC key up to release 1.86.
        try
        {
            PKCS12Util.validateMacKeyLength(BigInteger.valueOf(2000));
            fail("oversized MAC keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength 2000 greater than 1024", e.getMessage());
        }

        assertEquals(20, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(20)));
        assertEquals(64, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(64)));
        assertEquals(256, PKCS12Util.validateMacKeyLength(BigInteger.valueOf(256)));   // pre-1.87 files

        // and the encryption-side validator must NOT have picked the floor up
        assertEquals(16, PKCS12Util.validateKeyLength(BigInteger.valueOf(16)));
        assertEquals(32, PKCS12Util.validateKeyLength(BigInteger.valueOf(32)));

        try
        {
            PKCS12Util.validateKeyLength(BigInteger.ZERO);
            fail("zero keyLength accepted");
        }
        catch (IllegalStateException e)
        {
            assertEquals("keyLength must be positive", e.getMessage());
        }
    }

    /**
     * The PBMAC1 keyDerivationFunc field names the key-derivation function, so it carries id-PBKDF2
     * (RFC 9579 sec. 4, RFC 8018 app. A.2). This builder emitted id-PBES2 there, which BC's own
     * readers tolerate - they take the PBKDF2Params without looking at the OID - but the lightweight
     * BcPKCS12PBMac1CalculatorBuilder does not: it refuses anything else with "unrecognised PBKDF".
     */
    public void testJcePBMac1EmitsPbkdf2Oid()
        throws Exception
    {
        MacCalculator calculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setProvider(JslTestProvider.name()).build(passwd);

        PBMAC1Params params = PBMAC1Params.getInstance(calculator.getAlgorithmIdentifier().getParameters());

        assertEquals(PKCSObjectIdentifiers.id_PBKDF2, params.getKeyDerivationFunc().getAlgorithm());
    }

    /**
     * SHA-256 rather than the builder's SHA-1 default: JSL serves no SHA-1 PKCS#12 PBE MAC
     * ("no such algorithm: 1.3.14.3.2.26"), and a FIPS module would refuse it in any case. The
     * digest is scaffolding here - convertToDefiniteLength is what is under test.
     */
    private static PKCS12MacCalculatorBuilder pkcs12Mac()
    {
        return new JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256)
            .setProvider(JslTestProvider.name());
    }

    /**
     * JcePBMac1CalculatorBuilder does not implement PKCS12MacCalculatorBuilder - upstream drives
     * this fixture from the lightweight builder, which this fork does not carry. MacDataGenerator
     * calls build() before getDigestAlgorithmIdentifier(), and for PBMAC1 the identifier it wants is
     * the calculator's own.
     */
    private static PKCS12MacCalculatorBuilder pbMac1()
    {
        // 16 octets, not upstream's 8: a FIPS module refuses a shorter PBKDF2 salt outright
        // ("kdf_pbkdf2_set_ctx_params:invalid salt length"), per SP 800-132. Scaffolding either way.
        final JcePBMac1CalculatorBuilder builder = new JcePBMac1CalculatorBuilder(new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsaltsaltsalt"), 1024, 32,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256)))
            .setProvider(JslTestProvider.name());

        return new PKCS12MacCalculatorBuilder()
        {
            private MacCalculator calculator;

            public MacCalculator build(char[] password)
                throws OperatorCreationException
            {
                calculator = builder.build(password);

                return calculator;
            }

            public AlgorithmIdentifier getDigestAlgorithmIdentifier()
            {
                return calculator.getAlgorithmIdentifier();
            }
        };
    }

    private static PKCS12PfxPdu buildPfx(PKCS12MacCalculatorBuilder macBuilder)
        throws Exception
    {
        PKCS12SecretBag secret = new PKCS12SecretBagBuilder(
            CMSAlgorithm.AES256_CBC, new DEROctetString(new byte[]{1, 2, 3, 4}))
            .build();
        PKCS12SafeBag bag = new PKCS12SafeBagBuilder(secret).build();

        PKCS12PfxPduBuilder builder = new PKCS12PfxPduBuilder();
        builder.addData(bag);

        return builder.build(macBuilder, passwd);
    }
}
