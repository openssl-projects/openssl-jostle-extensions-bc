package org.bouncycastle.jsl.test;

import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.pkcs.util.PKCS12Util;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Round-trips RFC 9579 PBMAC1-protected PKCS#12 files through
 * {@link PKCS12Util#convertToDefiniteLength(byte[], char[], String)}, which recomputes the integrity
 * MAC. With the JSL provider this drives the aligned PBMAC1 path — PBKDF2 + HMAC via JSL/OpenSSL's
 * {@code SecretKeyFactory}/{@code Mac} (no software {@code PKCS5S2ParametersGenerator}/{@code HMac}).
 * The recomputed MAC is asserted equal to the MAC the original tool stored, so it proves JSL's PBMAC1
 * matches OpenSSL's and BouncyCastle's, end-to-end.
 */
public class PKCS12PBMAC1Test
    extends JostleProviderTestBase
{
    private static final char[] PASSWORD = "xxxxxx".toCharArray();

    private void implRoundTrip(String resource)
        throws Exception
    {
        InputStream in = TestResourceFinder.findTestResource("asn1", resource);
        byte[] pfxBytes = Streams.readAll(in);

        byte[] original = Pfx.getInstance(pfxBytes).getMacData().getMac().getDigest();
        assertNotNull(original);

        byte[] out = PKCS12Util.convertToDefiniteLength(pfxBytes, PASSWORD, JSL);

        byte[] recomputed = Pfx.getInstance(out).getMacData().getMac().getDigest();
        assertTrue("JSL-recomputed PBMAC1 MAC must match the stored MAC for " + resource,
            Arrays.areEqual(original, recomputed));
    }

    @Test
    public void pbmac1OpenSslFixtureRoundTrips()      // PBKDF2-HMAC-SHA256 + HMAC-SHA256
        throws Exception
    {
        implRoundTrip("test_key_pbmac1_openssl.pfx");
    }

    @Test
    public void pbmac1BcJsseFixtureRoundTrips()       // PBKDF2-HMAC-SHA256 + HMAC-SHA512
        throws Exception
    {
        implRoundTrip("test_key_pbmac1_bcjsse.pfx");
    }
}
