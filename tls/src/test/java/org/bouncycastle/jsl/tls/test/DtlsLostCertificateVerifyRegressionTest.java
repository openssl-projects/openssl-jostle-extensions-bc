package org.bouncycastle.jsl.tls.test;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.tls.DTLSClientProtocol;
import org.bouncycastle.jsl.tls.DTLSServerProtocol;
import org.bouncycastle.jsl.tls.DTLSTransport;
import org.bouncycastle.jsl.tls.DatagramTransport;
import org.bouncycastle.jsl.tls.HandshakeType;
import org.bouncycastle.jsl.util.Arrays;

import junit.framework.TestCase;

/**
 * Pins the one interleaving the DTLS epoch fix exists for: the client's CertificateVerify is lost
 * while the ChangeCipherSpec and Finished behind it arrive, so the server moves its read epoch on
 * and then has to accept the retransmission of a message belonging to the epoch it just left.
 * <p>
 * The loopback tests reach this only by chance, since they drop datagrams at random; here exactly
 * one datagram is dropped, so the cell fails on any build that discards the retransmission.
 */
public class DtlsLostCertificateVerifyRegressionTest
    extends TestCase
{
    /**
     * Client authentication over DTLS 1.2 signs a caller-supplied digest through NoneWithRSA,
     * which a FIPS module registers and refuses at initSign. A TestCase subclass cannot skip via
     * Assume, so the class returns early instead.
     */
    protected void runTest()
        throws Throwable
    {
        if (!JslTestProvider.canSign("NoneWithRSA", "RSA", 2048))
        {
            System.out.println("[skipped] " + getName() + ": " + JslTestProvider.name()
                + " cannot sign a caller-supplied digest with RSA");
            return;
        }

        super.runTest();
    }

    public void testHandshakeCompletesWhenCertificateVerifyIsLostAheadOfChangeCipherSpec()
        throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null);
        MockDTLSServer server = new MockDTLSServer();

        // The dropped message is only resent on the retransmit timer, so keep that short.
        client.setHandshakeResendTimeMillis(100);
        server.setHandshakeResendTimeMillis(100);

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        DTLSProtocolTest.ServerThread serverThread = new DTLSProtocolTest.ServerThread(
            new DTLSServerProtocol(), server, network.getServer());
        serverThread.start();

        DropOneHandshakeMessageDatagramTransport dropper = new DropOneHandshakeMessageDatagramTransport(
            network.getClient(), HandshakeType.certificate_verify);

        // No lossy layer to switch off, hence the null; the guard is here so a handshake that
        // stalls is reported instead of waiting forever.
        HandshakeGuardDatagramTransport guard = new HandshakeGuardDatagramTransport(dropper, null, serverThread);

        DatagramTransport clientTransport = guard;

        DTLSTransport dtlsClient = new DTLSClientProtocol().connect(client, clientTransport);
        guard.notifyHandshakeComplete();

        assertTrue("no CertificateVerify datagram was dropped, so this proves nothing",
            dropper.hasDropped());

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.fill(data, (byte)i);
            dtlsClient.send(data, 0, data.length);
        }

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        while (dtlsClient.receive(buf, 0, buf.length, 100) >= 0)
        {
        }

        dtlsClient.close();

        serverThread.shutdown();
    }
}
