package org.bouncycastle.jsl.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Production code must not resolve a provider by a name written into the source. A caller-supplied
 * name is fine; a literal binds this fork to whatever provider answers to it, which is how the
 * SunMSCAPI workaround stayed in the TLS crypto layer long after the fork stopped reaching any JDK
 * provider.
 * <p>
 * A source lint rather than a runtime cell, because the sites it guards are unreachable on this
 * platform and so no run would execute them.
 */
public class NoForeignProviderNameInProductionTest
{
    private static final String[] MODULES = {"core", "util", "pkix", "pg", "tls", "mail"};

    /** {@code Security.getProvider("...")} with a literal argument, in any spacing. */
    private static final Pattern LITERAL_GET_PROVIDER =
        Pattern.compile("Security\\s*\\.\\s*getProvider\\s*\\(\\s*\"([^\"]*)\"");

    @Test
    public void noProductionSourceResolvesAProviderByALiteralName()
        throws Exception
    {
        File root = repositoryRoot();

        List scanned = new ArrayList();
        List offences = new ArrayList();

        for (int i = 0; i != MODULES.length; i++)
        {
            File main = new File(root, MODULES[i] + "/src/main/java");
            if (!main.isDirectory())
            {
                fail("no main sources for module " + MODULES[i] + "; the lint is scanning the wrong tree");
            }
            scan(main, root, scanned, offences);
        }

        // Vacuity guard: a lint that reads nothing passes for the wrong reason.
        assertTrue("the lint read no production sources", scanned.size() > 1000);

        if (!offences.isEmpty())
        {
            fail("production source names a provider by literal: " + offences);
        }
    }

    /** The comment stripper has to blank a javadoc example without eating a real call. */
    @Test
    public void theCommentStripperKeepsCodeAndBlanksComments()
    {
        String comment = "// Security.getProvider(\"X\")";
        assertEquals("a comment must blank to spaces of the same length",
            comment.length(), stripComments(comment).length());
        assertEquals("a comment must blank to spaces",
            "", stripComments(comment).trim());

        assertTrue("a line comment must not survive",
            stripComments("// Security.getProvider(\"X\")").indexOf("getProvider") < 0);
        assertTrue("a block comment must not survive",
            stripComments("/* Security.getProvider(\"X\") */").indexOf("getProvider") < 0);
        assertTrue("a real call must survive",
            stripComments("Security.getProvider(\"X\");").indexOf("getProvider") >= 0);
        assertTrue("a slash inside a string is not a comment",
            stripComments("String s = \"// not a comment\"; Security.getProvider(\"X\");")
                .indexOf("getProvider") >= 0);
    }

    private void scan(File dir, File root, List scanned, List offences)
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
                scan(entry, root, scanned, offences);
            }
            else if (entry.getName().endsWith(".java"))
            {
                scanned.add(entry.getPath());

                Matcher m = LITERAL_GET_PROVIDER.matcher(stripComments(read(entry)));
                while (m.find())
                {
                    offences.add(relative(root, entry) + " -> " + m.group(1));
                }
            }
        }
    }

    /**
     * Blanks comments so a javadoc example is not read as a call site, leaving string literals
     * intact so a real argument still matches. Character positions are preserved.
     */
    static String stripComments(String source)
    {
        char[] out = source.toCharArray();

        final int CODE = 0, STRING = 1, CHAR = 2, LINE = 3, BLOCK = 4;
        int state = CODE;

        for (int i = 0; i < out.length; i++)
        {
            char c = out[i];
            char next = (i + 1 < out.length) ? out[i + 1] : ' ';

            switch (state)
            {
            case LINE:
                if (c == '\n')
                {
                    state = CODE;
                }
                else
                {
                    out[i] = ' ';
                }
                break;
            case BLOCK:
                if (c == '*' && next == '/')
                {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i++;
                    state = CODE;
                }
                else if (c != '\n')
                {
                    out[i] = ' ';
                }
                break;
            case STRING:
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    state = CODE;
                }
                break;
            case CHAR:
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '\'')
                {
                    state = CODE;
                }
                break;
            default:
                if (c == '/' && next == '/')
                {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i++;
                    state = LINE;
                }
                else if (c == '/' && next == '*')
                {
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i++;
                    state = BLOCK;
                }
                else if (c == '"')
                {
                    state = STRING;
                }
                else if (c == '\'')
                {
                    state = CHAR;
                }
                break;
            }
        }

        return new String(out);
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

    /** Walks up from the test's working directory to the directory holding settings.gradle. */
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
