package org.bouncycastle.jsl.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Production code resolves JCA services through a {@link org.bouncycastle.jsl.jcajce.util.JcaJceHelper}
 * so a caller who names no provider still gets this library's provider. A one-argument
 * {@code getInstance} goes straight to the JDK's installed order instead, which is what the helper
 * seam exists to avoid.
 * <p>
 * The allowlist below is the set of sites not yet moved, plus the certification-path sites that
 * stay on the JDK deliberately. It may only shrink: a cell pins its size, so a new bypass fails the
 * build rather than being added quietly.
 */
public class NoUnqualifiedServiceLookupInProductionTest
{
    private static final String[] MODULES = {"core", "util", "pkix", "pg", "tls", "mail"};

    /** The helper implementations are where naming a provider is decided; they are the seam. */
    private static final String[] SEAM = {
        "core/src/main/java/org/bouncycastle/jsl/jcajce/util/DefaultJcaJceHelper.java",
        "core/src/main/java/org/bouncycastle/jsl/jcajce/util/NamedJcaJceHelper.java",
        "core/src/main/java/org/bouncycastle/jsl/jcajce/util/ProviderJcaJceHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/cert/jcajce/DefaultCertHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/cert/jcajce/NamedCertHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/cert/jcajce/ProviderCertHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/jcajce/DefaultEACHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/jcajce/NamedEACHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/jcajce/ProviderEACHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/operator/jcajce/DefaultEACHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/operator/jcajce/NamedEACHelper.java",
        "pkix/src/main/java/org/bouncycastle/jsl/eac/operator/jcajce/ProviderEACHelper.java",
    };

    /** Sites that reach the JDK deliberately, each for the reason given beside it. */
    private static final String[] ALLOWED = {
        // the certification-path family: JSL's CertPathBuilder refuses a caller-supplied
        // PKIXCertPathChecker, which the TLS trust manager needs, and JSL serves no CertStore
        "pkix/src/main/java/org/bouncycastle/jsl/est/jcajce/JcaJceUtils.java",
        "tls/src/main/java/org/bouncycastle/jsl/jsse/provider/ProvX509TrustManager.java",
        // a JSSE key or trust store is a PKCS12 or JKS file, which JSL does not serve
        "tls/src/main/java/org/bouncycastle/jsl/jsse/provider/ProvKeyManagerFactorySpi.java",
        "tls/src/main/java/org/bouncycastle/jsl/jsse/provider/ProvTrustManagerFactorySpi.java",
    };

    /** JCA service type -> the import that tells it apart from a same-named ASN.1 class. */
    private static final String[][] SERVICES = {
        {"Cipher", "javax.crypto.Cipher"},
        {"Mac", "javax.crypto.Mac"},
        {"KeyAgreement", "javax.crypto.KeyAgreement"},
        {"KeyGenerator", "javax.crypto.KeyGenerator"},
        {"SecretKeyFactory", "javax.crypto.SecretKeyFactory"},
        {"ExemptionMechanism", "javax.crypto.ExemptionMechanism"},
        {"Signature", "java.security.Signature"},
        {"MessageDigest", "java.security.MessageDigest"},
        {"KeyFactory", "java.security.KeyFactory"},
        {"KeyPairGenerator", "java.security.KeyPairGenerator"},
        {"AlgorithmParameters", "java.security.AlgorithmParameters"},
        {"AlgorithmParameterGenerator", "java.security.AlgorithmParameterGenerator"},
        {"SecureRandom", "java.security.SecureRandom"},
        {"KeyStore", "java.security.KeyStore"},
        {"CertificateFactory", "java.security.cert.CertificateFactory"},
        {"CertStore", "java.security.cert.CertStore"},
        {"CertPathBuilder", "java.security.cert.CertPathBuilder"},
        {"CertPathValidator", "java.security.cert.CertPathValidator"},
    };

    @Test
    public void theAllowlistOnlyShrinks()
    {
        assertEquals("the allowlist may only shrink; a new entry needs a ruling",
            4, ALLOWED.length);
    }

    @Test
    public void noProductionSourceResolvesAServiceWithoutNamingAProvider()
        throws Exception
    {
        File root = repositoryRoot();

        Set seam = new HashSet(Arrays.asList(SEAM));
        Set allowed = new HashSet(Arrays.asList(ALLOWED));

        List scanned = new ArrayList();
        Set offenders = new TreeSet();
        Set allowedSeen = new TreeSet();

        for (int i = 0; i != MODULES.length; i++)
        {
            File main = new File(root, MODULES[i] + "/src/main/java");
            if (!main.isDirectory())
            {
                fail("no main sources for module " + MODULES[i] + "; the lint is scanning the wrong tree");
            }
            scan(main, root, seam, allowed, scanned, offenders, allowedSeen);
        }

        assertTrue("the lint read no production sources", scanned.size() > 1000);

        if (!offenders.isEmpty())
        {
            fail("production source resolves a JCA service without naming a provider: " + offenders);
        }

        // An allowlist entry that no longer offends is a stale entry: R13 must remove it.
        Set stale = new TreeSet(allowed);
        stale.removeAll(allowedSeen);
        if (!stale.isEmpty())
        {
            fail("allowlist entries no longer needed, remove them: " + stale);
        }
    }

    private void scan(File dir, File root, Set seam, Set allowed, List scanned, Set offenders, Set allowedSeen)
        throws IOException
    {
        File[] entries = dir.listFiles();
        if (entries == null)
        {
            return;
        }

        for (int i = 0; i != entries.length; i++)
        {
            File entry = entries[i];
            if (entry.isDirectory())
            {
                scan(entry, root, seam, allowed, scanned, offenders, allowedSeen);
                continue;
            }
            if (!entry.getName().endsWith(".java"))
            {
                continue;
            }

            String path = relative(root, entry).replace(File.separatorChar, '/');
            scanned.add(path);

            if (seam.contains(path))
            {
                continue;
            }

            String source = NoForeignProviderNameInProductionTest.stripComments(read(entry));
            if (!hasUnqualifiedLookup(source))
            {
                continue;
            }
            if (source.indexOf("DefaultProviderName.getProviderName()") >= 0)
            {
                // The file names the provider itself; the one-argument call is its null branch.
                continue;
            }

            if (allowed.contains(path))
            {
                allowedSeen.add(path);
            }
            else
            {
                offenders.add(path);
            }
        }
    }

    private static boolean hasUnqualifiedLookup(String source)
    {
        for (int i = 0; i != SERVICES.length; i++)
        {
            String type = SERVICES[i][0];
            if (source.indexOf("import " + SERVICES[i][1] + ";") < 0)
            {
                // A same-named ASN.1 class in the file's own package, not the JCA service.
                continue;
            }

            Matcher m = Pattern.compile("\\b" + type + "\\s*\\.\\s*getInstance\\s*\\(").matcher(source);
            while (m.find())
            {
                if (argumentCount(source, m.end() - 1) == 1)
                {
                    return true;
                }
            }
        }
        return false;
    }

    /** Counts top-level arguments from the open paren at {@code open}; 0 for an empty list. */
    private static int argumentCount(String source, int open)
    {
        int depth = 0;
        int args = 0;
        boolean seenToken = false;

        for (int i = open; i < source.length(); i++)
        {
            char c = source.charAt(i);
            if (c == '(' || c == '[')
            {
                depth++;
            }
            else if (c == ')' || c == ']')
            {
                depth--;
                if (depth == 0)
                {
                    return seenToken ? args + 1 : 0;
                }
            }
            else if (c == ',' && depth == 1)
            {
                args++;
            }
            else if (depth == 1 && !Character.isWhitespace(c))
            {
                seenToken = true;
            }
        }
        return -1;
    }

    private static String relative(File root, File file)
    {
        String prefix = root.getPath() + File.separator;
        String path = file.getPath();
        return path.startsWith(prefix) ? path.substring(prefix.length()) : path;
    }

    private static String read(File file)
        throws IOException
    {
        byte[] buf = new byte[(int)file.length()];
        InputStream in = new FileInputStream(file);
        try
        {
            int off = 0;
            while (off < buf.length)
            {
                int read = in.read(buf, off, buf.length - off);
                if (read < 0)
                {
                    break;
                }
                off += read;
            }
        }
        finally
        {
            in.close();
        }
        return new String(buf, Charset.forName("UTF-8"));
    }

    private static File repositoryRoot()
    {
        File dir = new File(System.getProperty("user.dir")).getAbsoluteFile();
        while (dir != null)
        {
            if (new File(dir, "settings.gradle").isFile())
            {
                return dir;
            }
            dir = dir.getParentFile();
        }
        throw new IllegalStateException("could not locate the repository root from "
            + System.getProperty("user.dir"));
    }
}
