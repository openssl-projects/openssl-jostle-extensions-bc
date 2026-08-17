package org.bouncycastle.tls.crypto.impl.jcajce;

import java.lang.reflect.Method;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsNonceGenerator;

class JcaNonceGenerator
    implements TlsNonceGenerator
{
    /**
     * java.security.DrbgParameters and the SecureRandomParameters overload of
     * SecureRandom.getInstance arrived in Java 9, but this module is compiled with --release 8, so
     * they are reached reflectively. Resolved once: on Java 8 every lookup fails and stays null.
     */
    private static final Method DRBG_INSTANTIATION;
    private static final Method GET_INSTANCE_WITH_PARAMS;
    private static final Object CAPABILITY_NONE;

    static
    {
        Method instantiation = null;
        Method getInstance = null;
        Object none = null;

        try
        {
            Class<?> drbgParameters = Class.forName("java.security.DrbgParameters");
            Class<?> capability = Class.forName("java.security.DrbgParameters$Capability");
            Class<?> parameters = Class.forName("java.security.SecureRandomParameters");

            instantiation = drbgParameters.getMethod("instantiation", int.class, capability, byte[].class);
            getInstance = SecureRandom.class.getMethod("getInstance", String.class, parameters, Provider.class);
            none = capability.getField("NONE").get(null);
        }
        catch (Exception e)
        {
            instantiation = null;
            getInstance = null;
            none = null;
        }

        DRBG_INSTANTIATION = instantiation;
        GET_INSTANCE_WITH_PARAMS = getInstance;
        CAPABILITY_NONE = none;
    }

    private final SecureRandom random;

    JcaNonceGenerator(SecureRandom entropySource, byte[] additionalData)
    {
        SecureRandom drbg = createDrbg(entropySource, additionalData);

        this.random = (null != drbg) ? drbg : entropySource;
    }

    /**
     * Ask the entropy source's own provider for a DRBG personalized with the connection's
     * additional seed material, so nonces for this connection are drawn from a distinct instance.
     * Returns null when the running JVM or that provider cannot supply one, in which case the
     * caller falls back to the entropy source itself and the additional data is not used - the
     * nonces are still drawn from a provider-managed source, they are just not personalized.
     */
    private static SecureRandom createDrbg(SecureRandom entropySource, byte[] additionalData)
    {
        if (null == DRBG_INSTANTIATION)
        {
            return null;
        }

        Provider provider = entropySource.getProvider();
        if (null == provider)
        {
            return null;
        }

        try
        {
            Object parameters = DRBG_INSTANTIATION.invoke(null, Integer.valueOf(-1), CAPABILITY_NONE,
                additionalData);

            return (SecureRandom)GET_INSTANCE_WITH_PARAMS.invoke(null, "DRBG", parameters, provider);
        }
        catch (Exception e)
        {
            // the provider registers no DRBG, or will not accept these parameters
            return null;
        }
    }

    public byte[] generateNonce(int size)
    {
        byte[] nonce = new byte[size];
        random.nextBytes(nonce);
        return nonce;
    }
}
