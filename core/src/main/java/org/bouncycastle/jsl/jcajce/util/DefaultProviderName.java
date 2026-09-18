package org.bouncycastle.jsl.jcajce.util;

/**
 * The name of the JCA provider that this library's own code asks for by name.
 * <p>
 * A few classes here have to name a provider rather than let the JCA choose one: a certificate
 * factory, a CRL or certificate signature verification, a CertStore, a CertPathBuilder, and the
 * content encryptor a CMP challenge is built with. bc-java hardcoded the BouncyCastle provider
 * name at each of those, which is wrong in this fork - there is no BouncyCastleProvider here - and
 * wrong for anyone who registers the provider under another name. Those sites read this instead.
 * <p>
 * The default is <code>"JSL"</code>, the name the Jostle provider registers under. Set it once,
 * before the library is used, if the provider is registered under another name (a FIPS build
 * registers as <code>"JSLFIPS"</code>).
 * <p>
 * A <code>null</code> name means "do not name a provider": each site falls back to the JCA's own
 * resolution, which takes the first provider in the installed order that serves the algorithm.
 * <p>
 * The value is read whenever a site needs it, so a change takes effect on the next call. It is not
 * synchronized beyond being volatile; setting it while other threads are using the library leaves
 * which of the two names a given call sees unspecified.
 */
public final class DefaultProviderName
{
    private static volatile String name = "JSL";

    private DefaultProviderName()
    {
    }

    /**
     * Return the provider name this library names, or null to name no provider.
     */
    public static String getProviderName()
    {
        return name;
    }

    /**
     * Set the provider name this library names.
     *
     * @param providerName the name the provider is registered under, or null to have the library
     *                     name no provider and let the JCA resolve each algorithm itself.
     */
    public static void setProviderName(String providerName)
    {
        name = providerName;
    }
}
