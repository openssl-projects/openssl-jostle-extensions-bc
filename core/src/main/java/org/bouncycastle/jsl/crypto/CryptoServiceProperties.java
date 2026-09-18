package org.bouncycastle.jsl.crypto;

public interface CryptoServiceProperties
{
    int bitsOfSecurity();

    String getServiceName();

    CryptoServicePurpose getPurpose();

    Object getParams();
}
