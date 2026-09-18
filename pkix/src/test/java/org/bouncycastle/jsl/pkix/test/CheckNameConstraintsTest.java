package org.bouncycastle.jsl.pkix.test;

import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.jsl.test.TestResourceFinder;

public class CheckNameConstraintsTest 
    extends TestCase
{
    public void testPKIXCertPathReviewer()
        throws Exception
    {
        JslTestProvider.install();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JslTestProvider.name());

        X509Certificate root = load(cf, "mal-root.crt");
        X509Certificate ca1 = load(cf, "mal-ca1.crt");
        X509Certificate ca2 = load(cf, "mal-ca2.crt");
        X509Certificate leaf = load(cf, "mal-leaf.crt");

        List certchain = new ArrayList();
        certchain.add(root);
        certchain.add(ca1);
        certchain.add(ca2);
        certchain.add(leaf);

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(root, null));
        PKIXParameters param = new PKIXParameters(trust);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        assertFalse(certPathReviewer.isValidCertPath()); // hit
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        JslTestProvider.install();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JslTestProvider.name());
        X509Certificate rootCert = load(cf, "mal-root.crt");
        X509Certificate endCert = load(cf, "mal-ca1.crt");

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params);

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date(1744869361113L)); // 17th April 2025
        buildParams.setRevocationEnabled(false);
        
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        JslTestProvider.install();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", JslTestProvider.name());

        X509Certificate rootCert = load(cf, "mal-root.crt");
        X509Certificate endCert = load(cf, "mal-ca1.crt");
        
        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);
        param.setDate(new Date(1744869361113L)); // 17th April 2025

        cpv.validate(certPath, param);
    }

    /**
     * These fixtures are about 1.2 MB each, over JSL's 1 MiB per-certificate ceiling. The ceiling is
     * read on every call, so raise it for the parse only and put the previous value back; the rest
     * of the JVM keeps the default. CertificateCeilingTest pins the refusal this lifts.
     */
    private static X509Certificate load(CertificateFactory cf, String fileName)
        throws Exception
    {
        String ceiling = "org.openssl.jostle.x509.max_certificate_bytes";
        String prior = System.getProperty(ceiling);
        System.setProperty(ceiling, Integer.toString(2 * 1024 * 1024));
        try
        {
            return (X509Certificate)cf.generateCertificate(
                TestResourceFinder.findTestResource("pkix", fileName));
        }
        finally
        {
            if (prior == null)
            {
                System.clearProperty(ceiling);
            }
            else
            {
                System.setProperty(ceiling, prior);
            }
        }
    }
}
