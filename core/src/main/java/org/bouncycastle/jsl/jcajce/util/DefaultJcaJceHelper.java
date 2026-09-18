package org.bouncycastle.jsl.jcajce.util;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanism;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

/**
 * {@link JcaJceHelper} used when a caller sets no provider. It names the provider
 * {@link DefaultProviderName} reports, so a caller who names none still resolves through this
 * library's own provider rather than through whatever the JDK's installed order happens to serve.
 * Setting that name to null restores the JDK's resolution.
 * <p>
 * The exception is the certification-path family: {@code CertPathBuilder} and
 * {@code CertPathValidator} are served by JSL but its builder refuses a caller-supplied
 * {@code PKIXCertPathChecker}, which the TLS trust manager needs; {@code CertStore},
 * {@code ExemptionMechanism} and the non-BCFKS {@code KeyStore} types are not served at all.
 * Those stay on the JDK deliberately, and say so at each method.
 */
public class DefaultJcaJceHelper
    implements JcaJceHelper
{
    public Cipher createCipher(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? Cipher.getInstance(algorithm)
            : Cipher.getInstance(algorithm, providerName);
    }

    public Mac createMac(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? Mac.getInstance(algorithm)
            : Mac.getInstance(algorithm, providerName);
    }

    public KeyAgreement createKeyAgreement(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? KeyAgreement.getInstance(algorithm)
            : KeyAgreement.getInstance(algorithm, providerName);
    }

    public AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? AlgorithmParameterGenerator.getInstance(algorithm)
            : AlgorithmParameterGenerator.getInstance(algorithm, providerName);
    }

    public AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? AlgorithmParameters.getInstance(algorithm)
            : AlgorithmParameters.getInstance(algorithm, providerName);
    }

    public KeyGenerator createKeyGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? KeyGenerator.getInstance(algorithm)
            : KeyGenerator.getInstance(algorithm, providerName);
    }

    public KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? KeyFactory.getInstance(algorithm)
            : KeyFactory.getInstance(algorithm, providerName);
    }

    public SecretKeyFactory createSecretKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? SecretKeyFactory.getInstance(algorithm)
            : SecretKeyFactory.getInstance(algorithm, providerName);
    }

    public KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? KeyPairGenerator.getInstance(algorithm)
            : KeyPairGenerator.getInstance(algorithm, providerName);
    }

    /** @deprecated Use createMessageDigest instead */
    public MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? MessageDigest.getInstance(algorithm)
            : MessageDigest.getInstance(algorithm, providerName);
    }

    public MessageDigest createMessageDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? MessageDigest.getInstance(algorithm)
            : MessageDigest.getInstance(algorithm, providerName);
    }

    public Signature createSignature(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? Signature.getInstance(algorithm)
            : Signature.getInstance(algorithm, providerName);
    }

    public CertificateFactory createCertificateFactory(String algorithm)
        throws CertificateException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? CertificateFactory.getInstance(algorithm)
            : CertificateFactory.getInstance(algorithm, providerName);
    }

    public SecureRandom createSecureRandom(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? SecureRandom.getInstance(algorithm)
            : SecureRandom.getInstance(algorithm, providerName);
    }

    /** JDK by intent: JSL's builder refuses a caller-supplied PKIXCertPathChecker. */
    public CertPathBuilder createCertPathBuilder(String algorithm)
        throws NoSuchAlgorithmException
    {
        return CertPathBuilder.getInstance(algorithm);
    }

    /** JDK by intent, for the same reason as {@link #createCertPathBuilder}. */
    public CertPathValidator createCertPathValidator(String algorithm)
        throws NoSuchAlgorithmException
    {
        return CertPathValidator.getInstance(algorithm);
    }

    /** JDK by intent: JSL serves no CertStore (measured). */
    public CertStore createCertStore(String type, CertStoreParameters params)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        return CertStore.getInstance(type, params);
    }

    /** JDK by intent: JSL serves no ExemptionMechanism (measured). */
    public ExemptionMechanism createExemptionMechanism(String algorithm)
        throws NoSuchAlgorithmException
    {
        return ExemptionMechanism.getInstance(algorithm);
    }

    /** JDK by intent: JSL serves only its own store type, not PKCS12 or JKS (measured). */
    public KeyStore createKeyStore(String type)
        throws KeyStoreException
    {
        return KeyStore.getInstance(type);
    }
}
