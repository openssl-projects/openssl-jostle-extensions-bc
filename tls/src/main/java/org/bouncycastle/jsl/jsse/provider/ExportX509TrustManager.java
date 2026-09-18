package org.bouncycastle.jsl.jsse.provider;

import org.bouncycastle.jsl.jsse.BCX509ExtendedTrustManager;

interface ExportX509TrustManager
{
    BCX509ExtendedTrustManager unwrap();
}
