package org.bouncycastle.jsl.tls;

import org.bouncycastle.jsl.tls.crypto.TlsCrypto;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(TlsCrypto crypto)
    {
        super(crypto, ConnectionEnd.client);
    }

    public boolean isServer()
    {
        return false;
    }
}
