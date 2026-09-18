package org.bouncycastle.jsl.tls;

import org.bouncycastle.jsl.tls.crypto.TlsCrypto;

class TlsServerContextImpl
    extends AbstractTlsContext
    implements TlsServerContext
{
    TlsServerContextImpl(TlsCrypto crypto)
    {
        super(crypto, ConnectionEnd.server);
    }

    public boolean isServer()
    {
        return true;
    }
}
