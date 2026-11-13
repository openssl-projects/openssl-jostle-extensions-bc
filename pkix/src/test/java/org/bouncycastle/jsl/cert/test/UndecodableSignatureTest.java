package org.bouncycastle.jsl.cert.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.jsl.asn1.ASN1EncodableVector;
import org.bouncycastle.jsl.asn1.DERBitString;
import org.bouncycastle.jsl.asn1.DERSequence;
import org.bouncycastle.jsl.asn1.pkcs.CertificationRequest;
import org.bouncycastle.jsl.asn1.x500.X500Name;
import org.bouncycastle.jsl.asn1.x509.Certificate;
import org.bouncycastle.jsl.asn1.x509.CertificateList;
import org.bouncycastle.jsl.cert.CertException;
import org.bouncycastle.jsl.cert.X509CRLHolder;
import org.bouncycastle.jsl.cert.X509CertificateHolder;
import org.bouncycastle.jsl.cert.X509v2CRLBuilder;
import org.bouncycastle.jsl.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jsl.operator.ContentSigner;
import org.bouncycastle.jsl.operator.ContentVerifierProvider;
import org.bouncycastle.jsl.operator.RuntimeOperatorException;
import org.bouncycastle.jsl.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jsl.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.jsl.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.jsl.pkcs.PKCSException;
import org.bouncycastle.jsl.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.jsl.util.BigIntegers;
import org.bouncycastle.jsl.util.encoders.Hex;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * An ECDSA signature that does not decode makes the JCA Signature throw SignatureException, which a
 * ContentVerifier can only pass on unchecked. The holders' isSignatureValid() methods report it as the
 * checked exception they declare, with the operator exception as the cause, rather than letting it out.
 */
public class UndecodableSignatureTest
    extends TestCase
{
    private static final String BC = JslTestProvider.name();

    // a DER SEQUENCE holding only r, where an ECDSA signature has r and s
    private static final byte[] UNDECODABLE = Hex.decode("3003020101");

    private KeyPair keyPair;
    private ContentSigner signer;
    private ContentVerifierProvider verifier;

    public void setUp()
        throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            JslTestProvider.install();
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(256);
        keyPair = kpg.generateKeyPair();
        signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(keyPair.getPrivate());
        verifier = new JcaContentVerifierProviderBuilder().setProvider(BC).build(keyPair.getPublic());
    }

    public void testCertificate()
        throws Exception
    {
        X500Name name = new X500Name("CN=Test");
        Date now = new Date();
        X509CertificateHolder valid = new JcaX509v3CertificateBuilder(name, BigIntegers.ONE, now,
            new Date(now.getTime() + 60000L), name, keyPair.getPublic()).build(signer);
        assertTrue(valid.isSignatureValid(verifier));

        Certificate c = valid.toASN1Structure();
        X509CertificateHolder tampered = new X509CertificateHolder(
            new Certificate(c.getTBSCertificate(), c.getSignatureAlgorithm(), new DERBitString(UNDECODABLE)));
        try
        {
            tampered.isSignatureValid(verifier);
            fail("undecodable certificate signature verified");
        }
        catch (CertException e)
        {
            assertTrue(e.getMessage().startsWith("unable to process signature: "));
            assertTrue(e.getCause() instanceof RuntimeOperatorException);
        }
    }

    public void testCRL()
        throws Exception
    {
        X509CRLHolder valid = new X509v2CRLBuilder(new X500Name("CN=Test"), new Date()).build(signer);
        assertTrue(valid.isSignatureValid(verifier));

        CertificateList crl = valid.toASN1Structure();
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(crl.getTBSCertList());
        v.add(crl.getSignatureAlgorithm());
        v.add(new DERBitString(UNDECODABLE));
        X509CRLHolder tampered = new X509CRLHolder(CertificateList.getInstance(new DERSequence(v)));
        try
        {
            tampered.isSignatureValid(verifier);
            fail("undecodable CRL signature verified");
        }
        catch (CertException e)
        {
            assertTrue(e.getMessage().startsWith("unable to process signature: "));
            assertTrue(e.getCause() instanceof RuntimeOperatorException);
        }
    }

    public void testCertificationRequest()
        throws Exception
    {
        PKCS10CertificationRequest valid = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Test"),
            keyPair.getPublic()).build(signer);
        assertTrue(valid.isSignatureValid(verifier));

        CertificationRequest r = valid.toASN1Structure();
        PKCS10CertificationRequest tampered = new PKCS10CertificationRequest(
            new CertificationRequest(r.getCertificationRequestInfo(), r.getSignatureAlgorithm(), new DERBitString(UNDECODABLE)));
        try
        {
            tampered.isSignatureValid(verifier);
            fail("undecodable request signature verified");
        }
        catch (PKCSException e)
        {
            assertTrue(e.getMessage().startsWith("unable to process signature: "));
            assertTrue(e.getCause() instanceof RuntimeOperatorException);
        }
    }
}
