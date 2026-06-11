package org.bouncycastle.cert.test;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class SampleCredentials
{
    // Loaded lazily and memoised per credential. Eager static-final fields caused
    // the whole class to fail initialisation (ExceptionInInitializerError, then a
    // cascading NoClassDefFoundError on every later access) when any one PEM was
    // absent from bc-test-data. With lazy accessors the class always initialises,
    // and only a test that actually references a missing credential fails — with a
    // direct error pointing at the missing resource.
    private static final java.util.Map<String, SampleCredentials> CACHE =
        new java.util.concurrent.ConcurrentHashMap<String, SampleCredentials>();

    public static SampleCredentials ML_DSA_44() { return get("ML-DSA-44", "pkix/cert/mldsa", "ML-DSA-44.pem"); }
    public static SampleCredentials ML_DSA_65() { return get("ML-DSA-65", "pkix/cert/mldsa", "ML-DSA-65.pem"); }
    public static SampleCredentials ML_DSA_87() { return get("ML-DSA-87", "pkix/cert/mldsa", "ML-DSA-87.pem"); }

    public static SampleCredentials ML_KEM_512() { return get("ML-KEM-512", "pkix/cert/mlkem", "ML-KEM-512.pem"); }
    public static SampleCredentials ML_KEM_768() { return get("ML-KEM-768", "pkix/cert/mlkem", "ML-KEM-768.pem"); }
    public static SampleCredentials ML_KEM_1024() { return get("ML-KEM-1024", "pkix/cert/mlkem", "ML-KEM-1024.pem"); }

    public static SampleCredentials SLH_DSA_SHA2_128S() { return get("SLH-DSA-SHA2-128S", "pkix/cert/slhdsa", "SLH-DSA-SHA2-128S.pem"); }

    private static SampleCredentials get(String algorithm, String path, String name)
    {
        SampleCredentials c = CACHE.get(algorithm);
        if (c == null)
        {
            c = load(algorithm, path, name);
            CACHE.put(algorithm, c);
        }
        return c;
    }

    private static PemObject expectPemObject(PemReader pemReader, String type)
        throws IOException
    {
        PemObject result = pemReader.readPemObject();
        if (!type.equals(result.getType()))
        {
            throw new IllegalStateException();
        }
        return result;
    }

    private static SampleCredentials load(String algorithm, String path, String name)
    {
        try
        {
            if (Security.getProvider("JSL") == null)
            {
                Security.addProvider(new JostleProvider());
            }

            InputStream input = new BufferedInputStream(TestResourceFinder.findTestResource(path, name));
            Reader reader = new InputStreamReader(input);

            PemReader pemReader = new PemReader(reader);
            PemObject pemPriv = expectPemObject(pemReader, "PRIVATE KEY");
            PemObject pemPub = expectPemObject(pemReader, "PUBLIC KEY");
            PemObject pemCert = expectPemObject(pemReader, "CERTIFICATE");
            pemReader.close();

            KeyFactory kf = KeyFactory.getInstance(algorithm, JostleProvider.PROVIDER_NAME);
            // Parse the cert through JSL so certificate.getPublicKey() yields a JSL
            // key matching kf.generatePublic(...) below. (When this helper was first
            // migrated JSL had no X.509 CertificateFactory and this fell back to the
            // JDK default, whose key wouldn't equals() the JSL-derived public key.)
            CertificateFactory cf = CertificateFactory.getInstance("X.509", JostleProvider.PROVIDER_NAME);

            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pemPriv.getContent()));
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pemPub .getContent()));
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            X509Certificate certificate = (X509Certificate)cf.generateCertificate(
                new ByteArrayInputStream(pemCert.getContent()));

            // Compare by encoded SubjectPublicKeyInfo rather than Object.equals():
            // JSL key implementations use identity equality, so two instances of the
            // same key (the one parsed here vs the one inside the certificate) are
            // never equals() even though they encode identically.
            if (!java.util.Arrays.equals(publicKey.getEncoded(), certificate.getPublicKey().getEncoded()))
            {
                throw new IllegalStateException("public key mismatch");
            }

            return new SampleCredentials(keyPair, certificate);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    private SampleCredentials(KeyPair keyPair, X509Certificate certificate)
    {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    public X509Certificate getCertificate()
    {
        return certificate;
    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }
}
