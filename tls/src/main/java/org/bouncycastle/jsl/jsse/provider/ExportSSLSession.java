package org.bouncycastle.jsl.jsse.provider;

import org.bouncycastle.jsl.jsse.BCExtendedSSLSession;

interface ExportSSLSession
{
    BCExtendedSSLSession unwrap();
}
