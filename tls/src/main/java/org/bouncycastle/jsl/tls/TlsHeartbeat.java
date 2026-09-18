package org.bouncycastle.jsl.tls;

public interface TlsHeartbeat
{
    byte[] generatePayload();

    int getIdleMillis();

    int getTimeoutMillis();
}
