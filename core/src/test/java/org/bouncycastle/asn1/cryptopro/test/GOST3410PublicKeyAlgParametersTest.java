package org.bouncycastle.asn1.cryptopro.test;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.util.Arrays;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The GOST public-key parameters encode one, two or three OIDs: the digest parameter set is
 * OPTIONAL for a GOST R 34.10-2012 key (RFC 9215 sec. 4.2) and required for a 2001 one, and the
 * encryption parameter set can only be the third element. Each form has to survive a round trip,
 * and a form the structure rules forbid has to be refused rather than encoded.
 */
public class GOST3410PublicKeyAlgParametersTest
{
    private static final ASN1ObjectIdentifier PUBLIC_KEY_PARAM_SET =
        CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A;
    private static final ASN1ObjectIdentifier DIGEST_PARAM_SET =
        CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet;
    private static final ASN1ObjectIdentifier ENCRYPTION_PARAM_SET =
        CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_ESDH;

    @Test
    public void oneElementSequenceRoundTrips()
        throws Exception
    {
        GOST3410PublicKeyAlgParameters decoded = roundTrip(
            new GOST3410PublicKeyAlgParameters(PUBLIC_KEY_PARAM_SET, null));

        assertEquals(PUBLIC_KEY_PARAM_SET, decoded.getPublicKeyParamSet());
        assertNull("digestParamSet must stay absent", decoded.getDigestParamSet());
        assertNull("encryptionParamSet must stay absent", decoded.getEncryptionParamSet());
    }

    @Test
    public void twoElementSequenceRoundTrips()
        throws Exception
    {
        GOST3410PublicKeyAlgParameters decoded = roundTrip(
            new GOST3410PublicKeyAlgParameters(PUBLIC_KEY_PARAM_SET, DIGEST_PARAM_SET));

        assertEquals(PUBLIC_KEY_PARAM_SET, decoded.getPublicKeyParamSet());
        assertEquals(DIGEST_PARAM_SET, decoded.getDigestParamSet());
        assertNull("encryptionParamSet must stay absent", decoded.getEncryptionParamSet());
    }

    @Test
    public void threeElementSequenceRoundTrips()
        throws Exception
    {
        GOST3410PublicKeyAlgParameters decoded = roundTrip(
            new GOST3410PublicKeyAlgParameters(PUBLIC_KEY_PARAM_SET, DIGEST_PARAM_SET, ENCRYPTION_PARAM_SET));

        assertEquals(PUBLIC_KEY_PARAM_SET, decoded.getPublicKeyParamSet());
        assertEquals(DIGEST_PARAM_SET, decoded.getDigestParamSet());
        assertEquals(ENCRYPTION_PARAM_SET, decoded.getEncryptionParamSet());
    }

    /**
     * The 1.2.643.2.2.30.0 test parameter set (RFC 4357 sec. 8.1) is a digest parameter set like
     * any other; it is named here because the OID itself is new.
     */
    @Test
    public void theTestDigestParamSetIsUsableAsADigestParamSet()
        throws Exception
    {
        GOST3410PublicKeyAlgParameters decoded = roundTrip(new GOST3410PublicKeyAlgParameters(
            PUBLIC_KEY_PARAM_SET, CryptoProObjectIdentifiers.gostR3411_94_TestParamSet));

        assertEquals(CryptoProObjectIdentifiers.gostR3411_94_TestParamSet, decoded.getDigestParamSet());
        assertEquals("1.2.643.2.2.30.0", CryptoProObjectIdentifiers.gostR3411_94_TestParamSet.getId());
    }

    @Test
    public void anEncryptionParamSetWithoutADigestParamSetIsRefused()
    {
        try
        {
            new GOST3410PublicKeyAlgParameters(PUBLIC_KEY_PARAM_SET, null, ENCRYPTION_PARAM_SET);
            fail("an encryptionParamSet without a digestParamSet was accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue("refusal did not name the missing element: " + e.getMessage(),
                e.getMessage().contains("digestParamSet"));
        }
    }

    @Test
    public void anAbsentPublicKeyParamSetIsRefused()
    {
        try
        {
            new GOST3410PublicKeyAlgParameters(null, DIGEST_PARAM_SET);
            fail("a null publicKeyParamSet was accepted");
        }
        catch (NullPointerException e)
        {
            assertTrue("refusal did not name the missing element: " + e.getMessage(),
                e.getMessage().contains("publicKeyParamSet"));
        }
    }

    private static GOST3410PublicKeyAlgParameters roundTrip(GOST3410PublicKeyAlgParameters params)
        throws Exception
    {
        byte[] encoded = params.getEncoded(ASN1Encoding.DER);

        GOST3410PublicKeyAlgParameters decoded = GOST3410PublicKeyAlgParameters.getInstance(encoded);

        assertArrayEquals("re-encoding must reproduce the same DER",
            encoded, decoded.getEncoded(ASN1Encoding.DER));
        assertTrue("the round trip must not change the encoding length",
            Arrays.areEqual(encoded, decoded.getEncoded(ASN1Encoding.DER)));

        return decoded;
    }
}
