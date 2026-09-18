package org.bouncycastle.jsl.tls;

import java.io.IOException;

public interface DatagramSender
{
    int getSendLimit() throws IOException;

    void send(byte[] buf, int off, int len) throws IOException;
}
