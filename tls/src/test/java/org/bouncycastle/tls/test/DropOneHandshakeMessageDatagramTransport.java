package org.bouncycastle.tls.test;

import java.io.IOException;

import org.bouncycastle.tls.DatagramTransport;

/**
 * Drops, exactly once, the first outgoing datagram that carries a chosen DTLS handshake message and
 * no ChangeCipherSpec record. Everything else passes through, so the records behind the dropped one
 * still arrive and the sender's retransmission of it is what the receiver has to accept.
 */
class DropOneHandshakeMessageDatagramTransport
    implements DatagramTransport
{
    private static final short CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
    private static final short CONTENT_TYPE_HANDSHAKE = 22;

    /** DTLSPlaintext: type(1) version(2) epoch(2) sequence_number(6) length(2). */
    private static final int RECORD_HEADER_LENGTH = 13;

    private final DatagramTransport transport;
    private final short handshakeType;

    private boolean dropped;

    DropOneHandshakeMessageDatagramTransport(DatagramTransport transport, short handshakeType)
    {
        this.transport = transport;
        this.handshakeType = handshakeType;
    }

    boolean hasDropped()
    {
        return dropped;
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (!dropped && carriesTargetWithoutChangeCipherSpec(buf, off, len))
        {
            dropped = true;
            return;
        }

        transport.send(buf, off, len);
    }

    /**
     * A datagram may carry several records. The message is only useful to drop while the
     * ChangeCipherSpec behind it still reaches the peer, so a datagram carrying both is passed on.
     */
    private boolean carriesTargetWithoutChangeCipherSpec(byte[] buf, int off, int len)
    {
        boolean found = false;

        int pos = off;
        int end = off + len;
        while (pos + RECORD_HEADER_LENGTH <= end)
        {
            short contentType = (short)(buf[pos] & 0xFF);
            int fragmentLength = ((buf[pos + 11] & 0xFF) << 8) | (buf[pos + 12] & 0xFF);
            int fragment = pos + RECORD_HEADER_LENGTH;
            if (fragment + fragmentLength > end)
            {
                return false;
            }

            if (contentType == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                return false;
            }
            if (contentType == CONTENT_TYPE_HANDSHAKE && fragmentLength > 0
                && (short)(buf[fragment] & 0xFF) == handshakeType)
            {
                found = true;
            }

            pos = fragment + fragmentLength;
        }

        return found;
    }

    public int getReceiveLimit()
        throws IOException
    {
        return transport.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        return transport.receive(buf, off, len, waitMillis);
    }

    public void close()
        throws IOException
    {
        transport.close();
    }
}
