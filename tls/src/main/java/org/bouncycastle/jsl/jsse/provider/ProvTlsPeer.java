package org.bouncycastle.jsl.jsse.provider;

import org.bouncycastle.jsl.tls.TlsContext;

interface ProvTlsPeer
{
    String getID();

    ProvSSLSession getSession();

    TlsContext getTlsContext();

    boolean isHandshakeComplete();
}
