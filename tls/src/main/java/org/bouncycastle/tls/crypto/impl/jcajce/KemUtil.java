package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Strings;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;
import org.openssl.jostle.jcajce.interfaces.MLKEMPublicKey;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.MLKEMParameterSpec;

class KemUtil
{
    private static KeyPairGenerator createKeyPairGenerator(JcaTlsCrypto crypto, String kemName)
        throws GeneralSecurityException
    {
        // TODO How to pass only the SecureRandom to initialize if we use the full name in the getInstance?
//        KeyPairGenerator keyPairGenerator = KemUtil.getKeyPairGenerator(crypto, kemName);
//        keyPairGenerator.initialize((AlgorithmParameterSpec)null, crypto.getSecureRandom());
        KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("ML-KEM");
        // JSL's MLKEMParameterSpec.fromName() keys on the lower-case parameter-set name.
        keyPairGenerator.initialize(MLKEMParameterSpec.fromName(Strings.toLowerCase(kemName)), crypto.getSecureRandom());
        return keyPairGenerator;
    }

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier oid, byte[] encoding)
        throws IOException
    {
        AlgorithmIdentifier algID = new AlgorithmIdentifier(oid);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
        return new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));
    }

    static JceTlsSecret decapsulate(JcaTlsCrypto crypto, String kemName, PrivateKey privateKey, byte[] ciphertext)
    {
        try
        {
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(KEMExtractSpec.builder()
                .withPrivate(privateKey)
                .withEncapsulatedKey(ciphertext)
                .withAlgorithmName("DEF")
                .withKeySizeInBits(256)
                .build());
            SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation)keyGenerator.generateKey();
            return crypto.adoptLocalSecret(secEnc.getEncoded());
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    static SecretKeyWithEncapsulation encapsulate(JcaTlsCrypto crypto, String kemName, PublicKey publicKey)
    {
        try
        {
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(KEMGenerateSpec.builder()
                .withPublicKey(publicKey)
                .withAlgorithmName("DEF")
                .withKeySizeInBits(256)
                .build());
            return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    static PublicKey decodePublicKey(JcaTlsCrypto crypto, String kemName, byte[] encoding) throws TlsFatalAlert
    {
        try
        {
            KeyFactory kf = crypto.getHelper().createKeyFactory(kemName);

            EncodedKeySpec keySpec = createX509EncodedKeySpec(getAlgorithmOID(kemName), encoding);
            return kf.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    static byte[] encodePublicKey(PublicKey publicKey) throws TlsFatalAlert
    {
        // More efficient BC-specific method
        if (publicKey instanceof MLKEMPublicKey)
        {
            return ((MLKEMPublicKey)publicKey).getPublicData();
        }

        if (!"X.509".equals(publicKey.getFormat()))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "Public key format unrecognized");
        }

        try
        {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            return spki.getPublicKeyData().getOctets();
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    static KeyPair generateKeyPair(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            return createKeyPairGenerator(crypto, kemName).generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    private static ASN1ObjectIdentifier getAlgorithmOID(String kemName)
    {
        if ("ML-KEM-512".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_512;
        }
        if ("ML-KEM-768".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_768;
        }
        if ("ML-KEM-1024".equalsIgnoreCase(kemName))
        {
            return NISTObjectIdentifiers.id_alg_ml_kem_1024;
        }

        throw new IllegalArgumentException("unknown kem name " + kemName);
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        if (kemName != null)
        {
            try
            {
                JcaJceHelper helper = crypto.getHelper();
                createKeyPairGenerator(crypto, kemName);
                helper.createKeyFactory(kemName);
                helper.createKeyGenerator(kemName);
                return true;
            }
            catch (AssertionError e)
            {
            }
            catch (Exception e)
            {
            }
        }
        return false;
    }
}
