package org.bouncycastle.jsl.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import junit.framework.TestCase;
import org.bouncycastle.jsl.est.ESTClientSourceProvider;
import org.bouncycastle.jsl.est.ESTRequestBuilder;
import org.bouncycastle.jsl.est.Source;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;

/**
 * DefaultESTClient writes request and header lines as UTF-8, whatever the platform charset.
 * In this package because DefaultESTClient is package-private.
 */
public class DefaultESTClientCharsetTest
    extends TestCase
{
    // U+201D is E2 80 9D in UTF-8; windows-1252 writes it as 0x94, and cannot encode U+65E5 at all.
    private static final byte[] PROBE = {
        'X', '-', 'P', 'r', 'o', 'b', 'e', ':', ' ', 'a',
        (byte)0xE2, (byte)0x80, (byte)0x9D, (byte)0xE6, (byte)0x97, (byte)0xA5, 'b', '\r', '\n' };

    public void testRequestHeaderEncodesAsUtf8()
        throws Exception
    {
        final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        final byte[] response = Strings.toByteArray("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        DefaultESTClient client = new DefaultESTClient(new ESTClientSourceProvider()
        {
            public Source makeSource(String host, int port)
            {
                return new Source<Object>()
                {
                    private final InputStream input = new ByteArrayInputStream(response);

                    public InputStream getInputStream()
                    {
                        return input;
                    }

                    public OutputStream getOutputStream()
                    {
                        return sent;
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
        });
        ESTRequestBuilder builder = new ESTRequestBuilder("GET", new URL("http://localhost/x"));
        builder.setHeader("X-Probe", "a\u201d\u65e5b");

        client.doRequest(builder.build());

        byte[] data = sent.toByteArray();
        boolean found = false;
        for (int i = 0; !found && i + PROBE.length <= data.length; i++)
        {
            found = Arrays.areEqual(PROBE, Arrays.copyOfRange(data, i, i + PROBE.length));
        }
        assertTrue(Strings.fromByteArray(data), found);
    }
}
