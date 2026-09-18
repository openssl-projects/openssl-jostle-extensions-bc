package org.bouncycastle.jsl.tls.crypto;

import org.bouncycastle.jsl.tls.TlsException;

/**
 * Basic exception class for crypto services to pass back a cause.
 */
public class TlsCryptoException
    extends TlsException
{
    public TlsCryptoException(String msg)
    {
        super(msg);
    }

    public TlsCryptoException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
