package org.bouncycastle.jsl.openpgp.operator.jcajce;

import java.security.Provider;

import org.bouncycastle.jsl.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jsl.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsl.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jsl.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.operator.PGPDigestCalculator;

class OperatorUtils
{
    static OperatorHelper createDefaultHelper()
    {
        return new OperatorHelper(new DefaultJcaJceHelper());
    }

    static OperatorHelper createProviderHelper(Provider provider)
    {
        return new OperatorHelper(providerHelper(provider));
    }

    /**
     * A null provider means the default provider search order. JcaOpenPGPImplementation's no-argument
     * constructor passes one, and ProviderJcaJceHelper refuses it with "missing provider".
     */
    static JcaJceHelper providerHelper(Provider provider)
    {
        return provider == null ? new DefaultJcaJceHelper() : new ProviderJcaJceHelper(provider);
    }

    static OperatorHelper createNamedHelper(String providerName)
    {
        return new OperatorHelper(new NamedJcaJceHelper(providerName));
    }

    /**
     * RFC 9980 sec. 5.3.1 and 6.2.1: a composite ML-DSA + EdDSA or an SLH-DSA signature MUST use a hash
     * algorithm with a digest size of at least 256 bits, and a verifier MUST reject one that does not.
     */
    static void checkPQCSignatureDigest(int keyAlgorithm, int hashAlgorithm, PGPDigestCalculator digestCalculator)
        throws PGPException
    {
        if (digestCalculator.getDigest().length < 32)
        {
            throw new PGPException("public key algorithm " + keyAlgorithm
                + " MUST use a hash algorithm with a digest size of at least 256 bits (RFC 9980), got hash algorithm "
                + hashAlgorithm);
        }
    }
}
