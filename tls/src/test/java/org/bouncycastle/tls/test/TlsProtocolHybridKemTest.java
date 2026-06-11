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
 * TLS 1.3 handshake coverage for the ML-KEM and NIST-curve key-exchange groups through the
 * JSL-backed {@link TlsCrypto}: the pure ML-KEM groups, the pure NIST ECDHE curves, and the
 * X25519/SecP + ML-KEM hybrids.
 * <p>
 * Driven over an external-PSK ({@code psk_dhe_ke}) exchange so the handshake exercises the
 * (hybrid) key agreement without requiring server certificate authentication. Groups whose
 * components the crypto does not support are skipped.
 */
public abstract class TlsProtocolHybridKemTest
    extends TestCase
{
    protected final TlsCrypto crypto;

    protected TlsProtocolHybridKemTest(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public void testMLKEM512() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM512);
    }

    public void testMLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM768);
    }

    public void testMLKEM1024() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM1024);
    }

    public void testX25519MLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.X25519MLKEM768);
    }

    public void testSecP256r1MLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.SecP256r1MLKEM768);
    }

    public void testSecP384r1MLKEM1024() throws Exception
    {
        implTestClientServer(NamedGroup.SecP384r1MLKEM1024);
    }

    public void testSecP256r1() throws Exception
    {
        implTestClientServer(NamedGroup.secp256r1);
    }

    public void testSecP384r1() throws Exception
    {
        implTestClientServer(NamedGroup.secp384r1);
    }

    public void testSecP521r1() throws Exception
    {
        implTestClientServer(NamedGroup.secp521r1);
    }

    private boolean supportsGroup(int namedGroup)
    {
        if (NamedGroup.refersToASpecificHybrid(namedGroup))
        {
            return crypto.hasNamedGroup(NamedGroup.getHybridFirst(namedGroup))
                && crypto.hasNamedGroup(NamedGroup.getHybridSecond(namedGroup));
        }
        return crypto.hasNamedGroup(namedGroup);
    }

    private void implTestClientServer(int namedGroup) throws Exception
    {
        if (!supportsGroup(namedGroup))
        {
            System.out.println("Skipping unsupported group " + NamedGroup.getText(namedGroup));
            return;
        }

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        KemClient client = new KemClient(namedGroup);
        KemServer server = new KemServer(namedGroup);

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

    static class KemClient
        extends MockPSKTls13Client
    {
        private final int namedGroup;
        int negotiatedGroup = -1;

        KemClient(int namedGroup)
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

    static class KemServer
        extends MockPSKTls13Server
    {
        private final int namedGroup;

        KemServer(int namedGroup)
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
