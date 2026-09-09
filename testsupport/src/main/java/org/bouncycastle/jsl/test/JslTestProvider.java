package org.bouncycastle.jsl.test;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jcajce.util.DefaultProviderName;
import org.junit.Assume;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

/**
 * Single point of provider selection for the migrated bc-java tests.
 * <p>
 * The suite always runs against the ordinary Jostle provider ("JSL"). When the
 * {@code TEST_FIPS_LIB} environment variable names a FIPS module, the {@code fipsTest} Gradle task
 * runs the same classes a second time against the FIPS provider ("JSLFIPS"), selected with
 * {@code -Dtest.jsl.provider=JSLFIPS}. Exactly one of the two is installed per run - see
 * {@link #install()} for why registering both breaks the FIPS pass.
 * <p>
 * The FIPS module is a much narrower surface than JSL - no Ed25519/Ed448, ML-DSA, ML-KEM,
 * X25519/X448, ChaCha20, Argon2, MD5, RIPEMD or SM3 - so tests needing something it does not
 * implement must gate themselves with {@link #assumeAlgorithm}. Gating rather than an
 * allow-list of classes is deliberate: an allow-list has to be kept in sync by hand, whereas a
 * gate is checked against the provider actually under test.
 */
public final class JslTestProvider
{
    public static final String JSL = JostleProvider.PROVIDER_NAME;
    public static final String JSLFIPS = JostleFIPSProvider.PROVIDER_NAME;

    /** System property naming the provider the suite should exercise. */
    public static final String SELECT_PROPERTY = "test.jsl.provider";

    /** Environment variable holding the full path to the FIPS module library. */
    public static final String FIPS_LIB_ENV = "TEST_FIPS_LIB";

    private JslTestProvider()
    {
    }

    /**
     * The FIPS module path, or null when unset or empty.
     */
    public static String fipsLib()
    {
        String lib = System.getenv(FIPS_LIB_ENV);

        return (null == lib || lib.trim().isEmpty()) ? null : lib.trim();
    }

    /**
     * The name of the provider under test - "JSL" unless {@link #SELECT_PROPERTY} says otherwise.
     */
    public static String name()
    {
        String sel = System.getProperty(SELECT_PROPERTY, JSL).trim();

        return sel.isEmpty() ? JSL : sel;
    }

    public static boolean isFips()
    {
        return JSLFIPS.equals(name());
    }

    /**
     * The one provider instance this JVM uses. Never replaced once built - see {@link #install()}.
     */
    private static Provider instance;

    /**
     * Register the provider under test and return it. Idempotent - the FIPS module's native
     * initialisation is one-shot per JVM, so an already-registered provider is reused rather than
     * replaced.
     * <p>
     * Exactly ONE Jostle provider is installed per run, the one named by {@link #SELECT_PROPERTY}.
     * Registering both would look harmless and quietly break the FIPS run: a key generated through
     * an unpinned lookup would come from whichever provider sits earlier in the list, and handing
     * a JSL private key to a JSLFIPS operator fails with "private key was created by a different
     * Jostle provider". Keeping one installed means every lookup, pinned or not, lands on the
     * provider actually under test.
     * <p>
     * And exactly ONE INSTANCE of it, for the lifetime of the JVM. A Jostle key is bound to the
     * provider instance that created it, public keys included, so a second instance under the same
     * name is not interchangeable with the first: an operator looked up through it refuses the
     * older instance's keys with "private key was created by a different Jostle provider
     * instance". That is easy to walk into here, because the {@code junit.extensions.TestSetup}
     * wrappers copied from bc-java remove the provider in {@code tearDown} while static key
     * generators - {@code CMSTestUtil}'s, for one - outlive the class that first built them. So
     * re-register the instance we already have rather than constructing another.
     */
    public static synchronized Provider install()
    {
        String want = name();

        if (null == instance)
        {
            if (JSLFIPS.equals(want))
            {
                String lib = fipsLib();
                if (null == lib)
                {
                    throw new IllegalStateException(JSLFIPS + " requested via " + SELECT_PROPERTY
                        + " but " + FIPS_LIB_ENV + " is not set");
                }
                // a set-but-broken path must fail loudly rather than silently skipping
                instance = new JostleFIPSProvider("fips_module='" + lib + "'");
            }
            else
            {
                instance = new JostleProvider();
            }
        }

        if (instance != Security.getProvider(want))
        {
            // either nothing is registered under that name, or something else is; in both cases
            // the run must end up with OUR instance registered
            Security.removeProvider(want);
            Security.addProvider(instance);
        }

        if (null == Security.getProvider(want))
        {
            throw new IllegalStateException("provider " + want + " requested via "
                + SELECT_PROPERTY + " but it is not available");
        }

        // A few library classes have to name a provider rather than let the JCA pick one - a
        // certificate factory, a CRL verification, a CertStore, a CertPathBuilder. They read
        // DefaultProviderName, whose default is "JSL". On a fipsTest leg only "JSLFIPS" is
        // registered, so leaving the default alone makes those sites ask for a provider that is
        // not there. Point it at whichever provider this run installed.
        //
        // Measured: without this, CheckNameConstraintsTest.testPKIXCertPathReviewer passes on JSL
        // and fails on both FIPS modules with "unable to rebuild certpath", which is
        // PKIXCertPathReviewer wrapping the NoSuchProviderException from its certificate factory.
        DefaultProviderName.setProviderName(want);

        return instance;
    }

    /**
     * The provider under test, installing it first. Use where a test needs the Provider object
     * rather than its name.
     */
    public static Provider provider()
    {
        return install();
    }

    /**
     * Skip the calling test unless the provider under test implements every one of the named
     * services, given as "Type.Algorithm" (e.g. "Signature.ED25519", "KeyPairGenerator.ML-KEM-768").
     * Under plain JSL this is nearly always a no-op; under JSLFIPS it is what keeps a test that
     * needs a non-approved algorithm from failing rather than skipping.
     */
    public static void assumeAlgorithm(String... typeDotAlgorithm)
    {
        Provider p = install();

        for (int i = 0; i != typeDotAlgorithm.length; i++)
        {
            String s = typeDotAlgorithm[i];
            int dot = s.indexOf('.');
            if (dot < 0)
            {
                throw new IllegalArgumentException("expected Type.Algorithm, got: " + s);
            }

            String type = s.substring(0, dot);
            String alg = s.substring(dot + 1);

            Assume.assumeTrue(name() + " does not implement " + s, null != p.getService(type, alg));
        }
    }

    /** cache: these probes generate keys, so do each combination once per JVM */
    private static final java.util.Map<String, Boolean> PROBES =
        new java.util.concurrent.ConcurrentHashMap<String, Boolean>();

    /**
     * Whether the provider under test can actually SIGN with this transformation.
     * <p>
     * A service lookup is not enough. A provider may register a signature and then refuse it at
     * {@code initSign} - JSLFIPS registers {@code NoneWithRSA} as a deliberate dead end, and refuses
     * SHA-1 signature generation while still serving SHA-1 verification. Only a real sign attempt
     * separates "registered" from "usable".
     */
    public static boolean canSign(String signatureAlgorithm, String keyAlgorithm, int keySize)
    {
        String key = name() + "|" + signatureAlgorithm + "|" + keyAlgorithm + "|" + keySize;

        Boolean cached = PROBES.get(key);
        if (null != cached)
        {
            return cached.booleanValue();
        }

        boolean usable;
        try
        {
            Provider p = install();
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(keyAlgorithm, p);
            kpg.initialize(keySize);
            java.security.Signature s = java.security.Signature.getInstance(signatureAlgorithm, p);
            s.initSign(kpg.generateKeyPair().getPrivate());
            s.update(new byte[8]);
            s.sign();
            usable = true;
        }
        catch (Exception e)
        {
            usable = false;
        }

        PROBES.put(key, Boolean.valueOf(usable));

        return usable;
    }

    /**
     * Whether the provider under test can actually INITIALISE this cipher transformation.
     * <p>
     * {@link #canGetCipher} is not enough for a mode: {@code Cipher.getInstance("AES/OCB/NoPadding")}
     * succeeds against JSLFIPS and only fails at {@code init}, when OpenSSL cannot fetch the mode.
     */
    public static boolean canInitCipher(String transformation)
    {
        String key = name() + "|init|" + transformation;

        Boolean cached = PROBES.get(key);
        if (null != cached)
        {
            return cached.booleanValue();
        }

        boolean usable;
        try
        {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(transformation, install());
            c.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"),
                new javax.crypto.spec.IvParameterSpec(new byte[12]));
            usable = true;
        }
        catch (Exception e)
        {
            usable = false;
        }

        PROBES.put(key, Boolean.valueOf(usable));

        return usable;
    }

    /**
     * Whether the provider under test can actually ENCRYPT with this transformation, given a key
     * and IV of the sizes the algorithm requires.
     * <p>
     * The no-argument {@link #canInitCipher} hardcodes a 32-byte AES key and a 12-byte IV, so it
     * answers "no" for any algorithm shaped differently even where that algorithm works.
     * <p>
     * DIRECTION matters, which is why this probes encryption specifically. A 3.5.8 FIPS module
     * serves Triple-DES for DECRYPTION and refuses encryption with a typed InvalidKeyException,
     * so "is DESede there" has no single answer. A 3.1.2 module has no Triple-DES at all, and the
     * failure then surfaces as a missing OID lookup instead - which is exactly why a gate must key
     * on a probe and never on the message text.
     */
    public static boolean canEncrypt(String transformation, String keyAlgorithm, int keyBytes,
        int ivBytes)
    {
        String key = name() + "|enc|" + transformation + "|" + keyAlgorithm + "|" + keyBytes
            + "|" + ivBytes;

        Boolean cached = PROBES.get(key);
        if (null != cached)
        {
            return cached.booleanValue();
        }

        boolean usable;
        try
        {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(transformation, install());
            javax.crypto.SecretKey k =
                new javax.crypto.spec.SecretKeySpec(new byte[keyBytes], keyAlgorithm);
            if (ivBytes > 0)
            {
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, k,
                    new javax.crypto.spec.IvParameterSpec(new byte[ivBytes]));
            }
            else
            {
                c.init(javax.crypto.Cipher.ENCRYPT_MODE, k);
            }
            c.doFinal(new byte[keyBytes]);
            usable = true;
        }
        catch (Exception e)
        {
            usable = false;
        }

        PROBES.put(key, Boolean.valueOf(usable));

        return usable;
    }

    /**
     * Skip the calling test unless a FIPS module is configured and selected.
     */
    public static void assumeFips()
    {
        Assume.assumeTrue(FIPS_LIB_ENV + " not set", null != fipsLib());
        Assume.assumeTrue("not running against " + JSLFIPS, isFips());
    }

    /**
     * Skip the calling test when running against the FIPS provider. Prefer
     * {@link #assumeAlgorithm} where the reason is a specific missing algorithm; use this only
     * where the test is structurally non-FIPS.
     */
    public static void assumeNotFips(String reason)
    {
        Assume.assumeFalse(reason, isFips());
    }

    /**
     * Convenience for the common "is this algorithm there" question without skipping.
     */
    public static boolean has(String type, String algorithm)
    {
        return null != install().getService(type, algorithm);
    }

    /**
     * JUnit3-safe gate. Returns false, having logged why, when the provider under test does not
     * implement everything named; the caller returns early.
     * <p>
     * {@link #assumeAlgorithm} cannot be used from a {@code junit.framework.TestCase} subclass:
     * those run under JUnit38ClassRunner, which reports an AssumptionViolatedException as a
     * FAILURE rather than a skip - the same trap that makes {@code @Ignore} useless there. Such a
     * test has to return early instead, so the skip is a log line rather than a skipped count.
     */
    public static boolean supports(String... typeDotAlgorithm)
    {
        Provider p = install();

        for (int i = 0; i != typeDotAlgorithm.length; i++)
        {
            String s = typeDotAlgorithm[i];
            int dot = s.indexOf('.');
            if (dot < 0)
            {
                throw new IllegalArgumentException("expected Type.Algorithm, got: " + s);
            }

            if (null == p.getService(s.substring(0, dot), s.substring(dot + 1)))
            {
                System.out.println("[skipped] " + name() + " does not implement " + s);
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the provider under test can actually build this Cipher transformation.
     * <p>
     * A service lookup cannot answer this: providers register the base algorithm ("AES"), so
     * getService("Cipher", "AES/OCB/NoPadding") is null even where the mode is fully supported.
     * Mode and padding support only surfaces on getInstance, so probe it.
     */
    public static boolean canGetCipher(String transformation)
    {
        try
        {
            javax.crypto.Cipher.getInstance(transformation, install());
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
    }

    /**
     * Skip the calling JUnit4 test unless the Cipher transformation can be built.
     */
    public static void assumeCipher(String transformation)
    {
        Assume.assumeTrue(name() + " cannot provide " + transformation, canGetCipher(transformation));
    }

    /**
     * Resolve a MessageDigest-style availability check that has to go through getInstance because
     * the algorithm is reached by an alias rather than a registered service name.
     */
    public static boolean canGetDigest(String algorithm)
    {
        try
        {
            java.security.MessageDigest.getInstance(algorithm, install());
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
    }
}
