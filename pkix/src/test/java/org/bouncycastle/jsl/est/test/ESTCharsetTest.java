package org.bouncycastle.jsl.est.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import junit.framework.TestCase;
import org.bouncycastle.jsl.est.ESTException;
import org.bouncycastle.jsl.est.ESTRequest;
import org.bouncycastle.jsl.est.ESTRequestBuilder;
import org.bouncycastle.jsl.est.ESTResponse;
import org.bouncycastle.jsl.est.HttpAuth;
import org.bouncycastle.jsl.est.Source;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;

/**
 * EST response header lines are read as UTF-8, whatever the platform charset.
 */
public class ESTCharsetTest
    extends TestCase
{
    // U+201D is E2 80 9D in UTF-8; windows-1252 leaves 0x9D undefined, so a 1252 decode cannot round-trip.
    private static final byte[] QUOTE = { (byte)0xE2, (byte)0x80, (byte)0x9D };

    // U+65E5 is E6 97 A5 in UTF-8; windows-1252 cannot encode it at all.
    private static final byte[] SUN = { (byte)0xE6, (byte)0x97, (byte)0xA5 };

    private static Source<Object> source(final byte[] in)
    {
        return new Source<Object>()
        {
            private final InputStream input = new ByteArrayInputStream(in);

            public InputStream getInputStream()
            {
                return input;
            }

            public OutputStream getOutputStream()
            {
                return new ByteArrayOutputStream();
            }

            public Object getSession()
            {
                return null;
            }

            public void close()
            {
            }
        };
    }

    private static ESTRequest get(String url)
        throws IOException
    {
        return new ESTRequestBuilder("GET", new URL(url)).build();
    }

    public void testResponseHeaderDecodesAsUtf8()
        throws Exception
    {
        byte[] response = Arrays.concatenate(
            Strings.toByteArray("HTTP/1.1 200 OK\r\nX-Probe: a"), QUOTE, SUN,
            Strings.toByteArray("b\r\nContent-Length: 0\r\n\r\n"));

        ESTResponse res = new ESTResponse(get("http://localhost/"), source(response));

        assertEquals("a\u201d\u65e5b", res.getHeader("X-Probe"));
    }

    // U+201D is not alpha, so the digest parser refuses the challenge and HttpAuth hands its bytes back.
    public void testUnparseableDigestChallengeKeepsItsUtf8Octets()
        throws Exception
    {
        ESTRequestBuilder builder = new ESTRequestBuilder("GET", new URL("http://localhost/x"));
        new HttpAuth("user", "password".toCharArray()).applyAuth(builder);
        ESTRequest req = builder.build();
        byte[] response = Arrays.concatenate(
            Strings.toByteArray("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest "), QUOTE,
            Strings.toByteArray("\r\nContent-Length: 0\r\n\r\n"));

        try
        {
            req.getHijacker().hijack(req, source(response));
            fail("an unparseable digest challenge must be refused");
        }
        catch (ESTException e)
        {
            byte[] expected = Arrays.concatenate(Strings.toByteArray("Digest "), QUOTE);
            byte[] body = Streams.readAll(e.getBody());
            assertTrue(Strings.fromByteArray(body), Arrays.areEqual(expected, body));
        }
    }
}
