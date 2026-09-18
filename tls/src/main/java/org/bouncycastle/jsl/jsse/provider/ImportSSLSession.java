package org.bouncycastle.jsl.jsse.provider;

import javax.net.ssl.SSLSession;

interface ImportSSLSession
{
    SSLSession unwrap();
}
