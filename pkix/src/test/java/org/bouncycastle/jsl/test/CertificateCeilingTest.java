package org.bouncycastle.jsl.test;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.test.TestResourceFinder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * JSL refuses a certificate larger than its per-certificate ceiling, and says which property lifts
 * it. {@code CheckNameConstraintsTest} raises that property around its own parses because its
 * fixtures are over the default; this pins the refusal those tests would otherwise hide, and pins
 * that the ceiling is read on every call rather than once.
 */
public class CertificateCeilingTest
    extends JostleProviderTestBase
{
    private static final String CEILING = "org.openssl.jostle.x509.max_certificate_bytes";

    /** mal-root.crt is 1223707 DER bytes, against a default ceiling of 1 MiB. */
    private static final int FIXTURE_BYTES = 1223707;

    @Test
    public void anOversizeCertificateIsRefusedUntilTheCeilingIsRaised()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);

        String prior = System.getProperty(CEILING);
        System.clearProperty(CEILING);
        try
        {
            try
            {
                cf.generateCertificate(fixture());
                fail("a " + FIXTURE_BYTES + " byte certificate was parsed under the default ceiling");
            }
            catch (CertificateParsingException e)
            {
                assertTrue("the refusal does not name the property that lifts it: " + e.getMessage(),
                    e.getMessage().indexOf(CEILING) >= 0);
            }

            System.setProperty(CEILING, Integer.toString(2 * 1024 * 1024));
            X509Certificate cert = (X509Certificate)cf.generateCertificate(fixture());
            assertEquals("the raised ceiling did not admit the whole certificate",
                FIXTURE_BYTES, cert.getEncoded().length);
        }
        finally
        {
            restore(prior);
        }
    }

    private static InputStream fixture()
        throws Exception
    {
        return TestResourceFinder.findTestResource("pkix", "mal-root.crt");
    }

    private static void restore(String prior)
    {
        if (prior == null)
        {
            System.clearProperty(CEILING);
        }
        else
        {
            System.setProperty(CEILING, prior);
        }
    }
}
