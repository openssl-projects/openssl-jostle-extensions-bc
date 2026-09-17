package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Vector;

import org.bouncycastle.jsl.test.JslTestProvider;
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
 * TLS 1.3 handshake coverage for the finite-field (FFDHE) named groups on JSL.
 * <p>
 * The FFDHE domain reaches the provider carrying its subgroup order Q, which only JSL's own
 * DHDomainParameterSpec conveys. A domain without Q still agrees a key, so nothing fails visibly -
 * this completes the handshake and asserts the group that was actually negotiated.
 * <p>
 * Driven over an external-PSK (psk_dhe_ke) exchange, so the DHE key agreement is exercised without
 * server certificate authentication, which is a separate concern from the key-exchange group.
 */
public class JcaTlsProtocolFfdheTest
    extends TestCase
{
    private final TlsCrypto crypto = TlsTestUtils.createTestCrypto();

    public void testFfdhe2048() throws Exception
    {
        implTestClientServer(NamedGroup.ffdhe2048);
    }

    public void testFfdhe3072() throws Exception
    {
        implTestClientServer(NamedGroup.ffdhe3072);
    }

    private void implTestClientServer(int namedGroup) throws Exception
    {
        if (!crypto.hasNamedGroup(namedGroup))
        {
            // A TestCase subclass cannot skip via Assume.
            System.out.println("[skipped] " + getName() + ": " + JslTestProvider.name()
                + " does not serve " + NamedGroup.getText(namedGroup));
            return;
        }

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        FfdheClient client = new FfdheClient(namedGroup);
        ServerThread serverThread = new ServerThread(serverProtocol, new FfdheServer(namedGroup));
        serverThread.start();

        clientProtocol.connect(client);

        // Written in full before anything is read, so this must stay within the pipe capacity.
        byte[] data = new byte[1000];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(data.length, count);
        assertTrue("echo did not match across the FFDHE handshake", Arrays.areEqual(data, echo));
        assertEquals("a different group was negotiated", namedGroup, client.negotiatedGroup);

        output.close();

        serverThread.join();
    }

    static class FfdheClient
        extends MockPSKTls13Client
    {
        private final int namedGroup;
        int negotiatedGroup = -1;

        FfdheClient(int namedGroup)
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

    static class FfdheServer
        extends MockPSKTls13Server
    {
        private final int namedGroup;

        FfdheServer(int namedGroup)
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
        Exception failure;

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
            catch (Exception e)
            {
                e.printStackTrace(System.out);
                this.failure = e;
            }
        }
    }
}
