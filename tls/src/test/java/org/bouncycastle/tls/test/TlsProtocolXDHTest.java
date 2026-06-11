package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Vector;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

/**
 * TLS 1.3 handshake coverage for the pure (non-hybrid) X25519 and X448 ECDHE named groups,
 * exercised through the JSL-backed {@link TlsCrypto}.
 * <p>
 * The handshake is driven over an external-PSK ({@code psk_dhe_ke}) exchange so that it exercises
 * the X25519/X448 (EC)DHE key agreement without requiring server certificate authentication (the
 * authentication signature algorithms are a separate concern from the key-exchange groups under
 * test here).
 */
public abstract class TlsProtocolXDHTest
    extends TestCase
{
    protected final TlsCrypto crypto;

    protected TlsProtocolXDHTest(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public void testX25519() throws Exception
    {
        implTestClientServer(NamedGroup.x25519);
    }

    public void testX448() throws Exception
    {
        implTestClientServer(NamedGroup.x448);
    }

    private void implTestClientServer(int namedGroup) throws Exception
    {
        if (!crypto.hasNamedGroup(namedGroup))
        {
            fail("crypto does not support named group " + NamedGroup.getText(namedGroup));
        }

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        XDHClient client = new XDHClient(namedGroup);
        XDHServer server = new XDHServer(namedGroup);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        assertEquals(namedGroup, client.negotiatedGroup);

        output.close();

        serverThread.join();
    }

    static class XDHClient
        extends MockPSKTls13Client
    {
        private final int namedGroup;
        int negotiatedGroup = -1;

        XDHClient(int namedGroup)
        {
            this.namedGroup = namedGroup;
        }

        public void notifyHandshakeComplete() throws IOException
        {
            super.notifyHandshakeComplete();
            this.negotiatedGroup = context.getSecurityParametersConnection().getNegotiatedGroup();
        }

        protected Vector getSupportedGroups(Vector namedGroupRoles)
        {
            Vector supportedGroups = new Vector();
            TlsUtils.addIfSupported(supportedGroups, getCrypto(), namedGroup);
            return supportedGroups;
        }

        public Vector getEarlyKeyShareGroups()
        {
            Vector v = new Vector();
            v.addElement(Integers.valueOf(namedGroup));
            return v;
        }
    }

    static class XDHServer
        extends MockPSKTls13Server
    {
        private final int namedGroup;

        XDHServer(int namedGroup)
        {
            this.namedGroup = namedGroup;
        }

        public int[] getSupportedGroups() throws IOException
        {
            return new int[]{ namedGroup };
        }
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final TlsServer server;

        ServerThread(TlsServerProtocol serverProtocol, TlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
    }
}
