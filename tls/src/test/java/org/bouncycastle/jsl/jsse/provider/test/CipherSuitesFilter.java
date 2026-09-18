package org.bouncycastle.jsl.jsse.provider.test;

interface CipherSuitesFilter
{
    boolean isIgnored(String cipherSuite);

    boolean isPermitted(String cipherSuite);
}
