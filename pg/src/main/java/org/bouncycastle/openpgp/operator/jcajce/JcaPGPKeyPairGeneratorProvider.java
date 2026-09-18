package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyPairGeneratorProvider;
// JSL accepts no foreign spec type, and registers no generic "XDH" generator - X25519 and X448
// are named services that need no parameters.
import org.openssl.jostle.jcajce.spec.EdDSAParameterSpec;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

public class JcaPGPKeyPairGeneratorProvider
    extends PGPKeyPairGeneratorProvider
{

    private OperatorHelper helper;
    private SecureRandom secureRandom = CryptoServicesRegistrar.getSecureRandom();

    public JcaPGPKeyPairGeneratorProvider()
    {
        this.helper = new OperatorHelper(new DefaultJcaJceHelper());
    }


    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider provider object for cryptographic primitives.
     * @return the current builder.
     */
    public JcaPGPKeyPairGeneratorProvider setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName the name of the provider to reference for cryptographic primitives.
     * @return the current builder.
     */
    public JcaPGPKeyPairGeneratorProvider setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        return this;
    }

    public JcaPGPKeyPairGeneratorProvider setSecureRandom(SecureRandom random)
    {
        this.secureRandom = random;
        return this;
    }


    @Override
    public PGPKeyPairGenerator get(int version, Date creationTime)
    {
        return new JcaPGPKeyPairGenerator(version, creationTime, helper, secureRandom);
    }

    private static class JcaPGPKeyPairGenerator
        extends PGPKeyPairGenerator
    {

        private final OperatorHelper helper;

        public JcaPGPKeyPairGenerator(int version, Date creationTime, OperatorHelper helper, SecureRandom random)
        {
            super(version, creationTime, random, new JcaKeyFingerprintCalculator());
            this.helper = helper;
        }

        @Override
        public PGPKeyPair generateRsaKeyPair(BigInteger exponent, int bitStrength)
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("RSA");
                gen.initialize(new RSAKeyGenParameterSpec(bitStrength, exponent));
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.RSA_GENERAL, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate RSA key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateEd25519KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(EdDSAParameterSpec.ED25519);
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed25519, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate Ed25519 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateEd448KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(EdDSAParameterSpec.ED448);
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.Ed448, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate Ed448 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateX25519KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("X25519");
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.X25519, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate X25519 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateX448KeyPair()
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("X448");
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.X448, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate X448 key pair", e);
            }
        }

        @Override
        public PGPKeyPair generateLegacyEd25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyEd25519 key pair.");
            }

            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EDDSA");
                gen.initialize(EdDSAParameterSpec.ED25519);
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.EDDSA_LEGACY, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate LegacyEd25519 key pair.");
            }
        }

        @Override
        public PGPKeyPair generateLegacyX25519KeyPair()
            throws PGPException
        {
            if (version == PublicKeyPacket.VERSION_6)
            {
                throw new PGPException("An implementation MUST NOT generate a v6 LegacyX25519 key pair.");
            }

            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("X25519");
                KeyPair keyPair = gen.generateKeyPair();
                return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH, keyPair, creationTime);
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate LegacyX25519 key pair.", e);
            }
        }

        @Override
        public PGPKeyPair generateECDHKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDH,
                generateEC(curveOID, "ECDH"), creationTime);
        }

        @Override
        public PGPKeyPair generateECDSAKeyPair(ASN1ObjectIdentifier curveOID)
            throws PGPException
        {
            return new JcaPGPKeyPair(version, PublicKeyAlgorithmTags.ECDSA,
                generateEC(curveOID, "ECDSA"), creationTime);
        }

        // JSL serves one EC generator, named "EC", and takes the curve as an OID through the
        // JCA-standard ECGenParameterSpec. There is no "ECDH" or "ECDSA" generator to ask for.
        private KeyPair generateEC(ASN1ObjectIdentifier curveOID, String use)
            throws PGPException
        {
            try
            {
                KeyPairGenerator gen = helper.createKeyPairGenerator("EC");
                gen.initialize(new ECGenParameterSpec(curveOID.getId()));
                return gen.generateKeyPair();
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("Cannot generate EC (" + use + ") key pair for curve "
                    + curveOID.getId() + ".", e);
            }
        }
    }
}
