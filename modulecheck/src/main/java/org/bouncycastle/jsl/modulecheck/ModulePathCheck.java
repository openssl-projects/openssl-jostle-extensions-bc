package org.bouncycastle.jsl.modulecheck;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

/**
 * Runs the built jars as a modular consumer sees them. Every other leg puts them on the class
 * path, where the module system is off and neither a split package nor a wrong module name can
 * be noticed.
 * <p>
 * The cell is declared by {@code jsl.module.cell}: on the module path the types must resolve to
 * their own named modules, on the class path they must all land in the unnamed module. The
 * class-path cell is the control, and it is what makes these assertions about the module path
 * rather than about the types.
 */
public class ModulePathCheck
{
    private static final boolean ON_MODULE_PATH = "modulepath".equals(System.getProperty("jsl.module.cell"));

    private static final int EXPECTED_JDK = Integer.parseInt(System.getProperty("jsl.module.jdk", "0"));

    /**
     * One type per bundle, and the module name a consumer types in its own module-info. These
     * names are kept when real descriptors replace the automatic ones, so a rename fails here
     * instead of in a user's build.
     */
    private static final Object[][] MODULES = {
        {ASN1ObjectIdentifier.class,  "org.bouncycastle.jsl.core"},
        {PKIBody.class,               "org.bouncycastle.jsl.util"},
        {X509CertificateHolder.class, "org.bouncycastle.jsl.pkix"},
        {PGPPublicKey.class,          "org.bouncycastle.jsl.pg"},
        {TlsUtils.class,              "org.bouncycastle.jsl.tls"},
        {SMIMEException.class,        "org.bouncycastle.jsl.mail"},
        {JostleProvider.class,        "org.openssl.jostle.prov"},
    };

    /**
     * A leg named for a JDK that silently ran on another one proves nothing about that JDK. The
     * toolchain is resolved by Gradle, so this is the only place the choice is checked.
     */
    @Test
    public void ranOnTheJdkTheLegIsNamedFor()
    {
        assertEquals("leg ran on the wrong JDK", EXPECTED_JDK, Runtime.version().feature());
    }

    @Test
    public void moduleIdentities()
    {
        for (Object[] row : MODULES)
        {
            Class<?> type = (Class<?>)row[0];
            String expected = (String)row[1];
            Module module = type.getModule();

            if (ON_MODULE_PATH)
            {
                assertTrue(type.getName() + " resolved outside a named module", module.isNamed());
                assertEquals(type.getName(), expected, module.getName());
            }
            else
            {
                assertFalse(type.getName() + " is in a named module on the class path", module.isNamed());
                assertNull(type.getName() + " carries a module name on the class path", module.getName());
            }
        }
    }

    /**
     * A descriptor that exports less than the jar holds is invisible until a consumer reaches for
     * the missing package. The bundle guard asserts the jar's contents against what the module
     * compiled; this asserts the descriptor against the same set, so the two cannot drift.
     */
    @Test
    public void exportsMatchContents()
    {
        for (Object[] row : MODULES)
        {
            Class<?> type = (Class<?>)row[0];
            Module module = type.getModule();

            if (!ON_MODULE_PATH)
            {
                assertNull(type.getName() + " has a descriptor on the class path", module.getDescriptor());
                continue;
            }

            if (!module.getName().startsWith("org.bouncycastle.jsl."))
            {
                continue;
            }

            Set<String> exported = new TreeSet<String>();
            for (java.lang.module.ModuleDescriptor.Exports e : module.getDescriptor().exports())
            {
                exported.add(e.source());
            }

            // Same exclusion as the bnd export pattern.
            Set<String> held = new TreeSet<String>();
            for (String p : module.getPackages())
            {
                if (!p.startsWith("org.bouncycastle.internal."))
                {
                    held.add(p);
                }
            }

            assertEquals(module.getName(), held, exported);
        }
    }

    /**
     * The descriptor's provides clause and the class-path services file must agree, or the JSSE
     * provider is discoverable on one path and not the other.
     */
    @Test
    public void jsseProviderIsDiscoverableAsAService()
    {
        boolean found = false;

        for (ServiceLoader.Provider<Provider> candidate : ServiceLoader.load(Provider.class).stream()
            .collect(java.util.stream.Collectors.toList()))
        {
            if ("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider".equals(candidate.type().getName()))
            {
                found = true;
            }
        }

        assertTrue("BouncyCastleJsseProvider was not found by ServiceLoader", found);
    }

    /**
     * mail's javax dependences are {@code requires static}, so they resolve only when named. This
     * fails with NoClassDefFoundError rather than an assertion if they were not, which is the
     * point: an identity pin on a type that extends java.lang.Exception would pass while the
     * module was unusable.
     */
    @Test
    public void mailReachesJavaxMail()
        throws Exception
    {
        Class<?> smimeUtil = Class.forName("org.bouncycastle.mail.smime.SMIMEUtil");
        boolean touches = false;

        for (Method method : smimeUtil.getDeclaredMethods())
        {
            for (Class<?> parameter : method.getParameterTypes())
            {
                if (parameter.getName().startsWith("javax.mail"))
                {
                    touches = true;
                }
            }
        }

        assertTrue("SMIMEUtil resolved no javax.mail parameter type", touches);
    }

    /**
     * Resolution proves nothing about reachability: the provider must still answer across the
     * module boundary, and SHA-256 reaches OpenSSL rather than staying in Java.
     */
    @Test
    public void providerAnswersAcrossTheModuleBoundary()
        throws Exception
    {
        Provider provider = new JostleProvider();

        Security.addProvider(provider);

        MessageDigest digest = MessageDigest.getInstance("SHA-256", provider.getName());

        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Hex.toHexString(digest.digest("abc".getBytes("UTF-8"))));
    }
}
