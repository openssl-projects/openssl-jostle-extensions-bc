package org.bouncycastle.jsl.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;

/**
 * Diagnostic for the ML-DSA SPKI encoding mismatch:
 * dumps (a) the source SubjectPublicKeyInfo from the PEM, (b) the encoding via
 * KeyFactory, and (c) the encoding via the X.509 cert public key, then reports
 * the first byte where they diverge.
 */
public class MLDsaEncodingDiagTest
    extends JostleProviderTestBase
{
    @Test
    public void diag()
        throws Exception
    {
        String algorithm = "ML-DSA-44";
        InputStream input = new BufferedInputStream(
            TestResourceFinder.findTestResource("pkix/cert/mldsa", "ML-DSA-44.pem"));
        Reader reader = new InputStreamReader(input);
        PemReader pemReader = new PemReader(reader);
        PemObject pemPriv = pemReader.readPemObject();
        PemObject pemPub = pemReader.readPemObject();
        PemObject pemCert = pemReader.readPemObject();
        pemReader.close();

        KeyFactory kf = KeyFactory.getInstance(algorithm, JSL);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", JSL);

        byte[] source = pemPub.getContent();
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(source));
        X509Certificate cert = (X509Certificate)cf.generateCertificate(
            new ByteArrayInputStream(pemCert.getContent()));
        PublicKey certKey = cert.getPublicKey();
        System.out.println("KeyFactory provider     : " + kf.getProvider().getName());
        System.out.println("CertificateFactory prov : " + cf.getProvider().getName());
        System.out.println("Certificate impl class  : " + cert.getClass().getName());
        System.out.println("cert key getAlgorithm()  : " + certKey.getAlgorithm());
        try { KeyFactory.getInstance(certKey.getAlgorithm(), JSL); System.out.println("JSL KF by that name: OK"); }
        catch (Exception e) { System.out.println("JSL KF by that name: " + e); }

        byte[] viaKf = publicKey.getEncoded();
        byte[] viaCert = certKey.getEncoded();

        System.out.println("=== ML-DSA SPKI encoding diag ===");
        System.out.println("source PEM SPKI : len=" + source.length);
        System.out.println("KeyFactory key  : class=" + publicKey.getClass().getName() + " len=" + viaKf.length);
        System.out.println("Cert public key : class=" + certKey.getClass().getName() + " len=" + viaCert.length);
        System.out.println("source == viaKf  : " + java.util.Arrays.equals(source, viaKf));
        System.out.println("source == viaCert: " + java.util.Arrays.equals(source, viaCert));
        System.out.println("viaKf  == viaCert: " + java.util.Arrays.equals(viaKf, viaCert));
        report("source", "viaKf", source, viaKf);
        report("source", "viaCert", source, viaCert);
        report("viaKf", "viaCert", viaKf, viaCert);
    }

    private static void report(String an, String bn, byte[] a, byte[] b)
    {
        int n = Math.min(a.length, b.length);
        int d = -1;
        for (int i = 0; i < n; i++) { if (a[i] != b[i]) { d = i; break; } }
        if (d < 0 && a.length == b.length) { System.out.println(an + " vs " + bn + ": identical"); return; }
        if (d < 0) { d = n; }
        System.out.println(an + " vs " + bn + ": first diff at offset " + d
            + " (lenA=" + a.length + " lenB=" + b.length + ")");
        int s = Math.max(0, d - 8), e = Math.min(n, d + 24);
        System.out.println("  head " + an + " [0..40): " + Hex.toHexString(a, 0, Math.min(40, a.length)));
        System.out.println("  head " + bn + " [0..40): " + Hex.toHexString(b, 0, Math.min(40, b.length)));
        System.out.println("  " + an + " [" + s + ".." + e + "): " + Hex.toHexString(a, s, e - s));
        System.out.println("  " + bn + " [" + s + ".." + e + "): " + Hex.toHexString(b, s, e - s));
    }
}
