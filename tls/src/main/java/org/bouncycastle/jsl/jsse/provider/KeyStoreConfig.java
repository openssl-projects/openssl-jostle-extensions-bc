package org.bouncycastle.jsl.jsse.provider;

import java.security.KeyStore;

class KeyStoreConfig
{
    final KeyStore keyStore;
    final char[] password;

    KeyStoreConfig(KeyStore keyStore, char[] password)
    {
        this.keyStore = keyStore;
        this.password = password;
    }
}
