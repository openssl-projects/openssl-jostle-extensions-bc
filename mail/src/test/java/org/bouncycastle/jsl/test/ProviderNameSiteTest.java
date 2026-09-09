package org.bouncycastle.jsl.test;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.util.DefaultProviderName;
import org.bouncycastle.mail.smime.validator.SignedMailValidator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Covers a {@link DefaultProviderName} site with a real call.
 * <p>
 * A handful of library classes have to name a provider rather than let the JCA choose one, and they
 * read {@code DefaultProviderName}. Almost none of those sites is reached by any test: set the name
 * to a value no provider answers to and the whole suite stays green apart from the core test that
 * asserts the default, which is why the FIPS legs once passed while every one of those sites was
 * asking for a provider that was not registered.
 * <p>
 * {@code SignedMailValidator.createCertPath} is the cheapest reachable one - public, static, and it
 * needs a certificate rather than a signed message.
 * <p>
 * Which site this covers was narrowed by falsification, not by reading: reverting BOTH of
 * SignedMailValidator's name-reading helpers to a literal makes the nonsense case fail; reverting
 * only {@code createCertificateFactory} also makes it fail; reverting only {@code verify} leaves it
 * passing. So this test throws at the certificate factory, {@code createCertificateFactory}, and
 * does NOT reach the four {@code cert.verify(key, provider)} sites - those stay uncovered.
 * <p>
 * That makes two of the thirteen provider-name sites covered by the suite, the other being
 * PKIXCertPathReviewer's certificate factory via CheckNameConstraintsTest.
 */
public class ProviderNameSiteTest
{
    private final String original = DefaultProviderName.getProviderName();

    @After
    public void restore()
    {
        DefaultProviderName.setProviderName(original);
    }

    /**
     * The point of the test: with a name no provider answers to, the site must fail and say so. If
     * this ever passes, the site has stopped reading DefaultProviderName.
     */
    @Test
    public void testNonsenseProviderNameIsReported()
        throws Exception
    {
        X509Certificate cert = selfSigned();

        DefaultProviderName.setProviderName("NOSUCHPROVIDER");
        try
        {
            SignedMailValidator.createCertPath(cert, trustAnchors(cert), noCertStores());
            fail("expected the site to reject an unregistered provider name");
        }
        catch (GeneralSecurityException e)
        {
            NoSuchProviderException nspe = findNoSuchProvider(e);
            assertNotNull("expected a NoSuchProviderException in the cause chain, got " + e, nspe);
            assertTrue("the failure should name the provider asked for, was: " + nspe.getMessage(),
                nspe.getMessage().contains("NOSUCHPROVIDER"));
        }
    }

    /**
     * A null name means "do not name a provider", so the same call has to resolve through the JCA's
     * own lookup instead of failing.
     */
    @Test
    public void testNullNameResolvesThroughTheJcaDefault()
        throws Exception
    {
        X509Certificate cert = selfSigned();

        DefaultProviderName.setProviderName(null);

        CertPath path = SignedMailValidator.createCertPath(cert, trustAnchors(cert), noCertStores());
        assertNotNull(path);
    }

    /**
     * Control: the name the run actually installed works. Without this a broken fixture would look
     * like a passing nonsense-name assertion.
     */
    @Test
    public void testInstalledProviderNameWorks()
        throws Exception
    {
        X509Certificate cert = selfSigned();

        DefaultProviderName.setProviderName(JslTestProvider.name());

        CertPath path = SignedMailValidator.createCertPath(cert, trustAnchors(cert), noCertStores());
        assertNotNull(path);
    }

    private static NoSuchProviderException findNoSuchProvider(Throwable t)
    {
        for (Throwable c = t; null != c; c = c.getCause())
        {
            if (c instanceof NoSuchProviderException)
            {
                return (NoSuchProviderException)c;
            }
        }
        return null;
    }

    private static Set trustAnchors(X509Certificate cert)
    {
        Set anchors = new HashSet();
        anchors.add(new TrustAnchor(cert, null));
        return anchors;
    }

    private static java.util.List noCertStores()
    {
        return new ArrayList();
    }

    private static X509Certificate selfSigned()
        throws Exception
    {
        JslTestProvider.install();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JslTestProvider.name());
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=Provider Name Site Test");
        Date from = new Date(System.currentTimeMillis() - 60 * 60 * 1000L);
        Date to = new Date(System.currentTimeMillis() + 24L * 60 * 60 * 1000L);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(JslTestProvider.name()).build(kp.getPrivate());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            dn, BigInteger.valueOf(System.currentTimeMillis()), from, to, dn, kp.getPublic());

        return new JcaX509CertificateConverter()
            .setProvider(JslTestProvider.name()).getCertificate(builder.build(signer));
    }
}
