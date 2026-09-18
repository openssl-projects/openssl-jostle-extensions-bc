package org.bouncycastle.jsl.tls.test;

import org.bouncycastle.jsl.tls.DTLSServerProtocol;

class DTLSTestServerProtocol extends DTLSServerProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestServerProtocol(TlsTestConfig config)
    {
        super();

        this.config = config;
    }
}
