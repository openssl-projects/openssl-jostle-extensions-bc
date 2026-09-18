package org.bouncycastle.jsl.tls;

import org.bouncycastle.jsl.tls.crypto.TlsSecret;

public interface TlsPSK
{
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}
