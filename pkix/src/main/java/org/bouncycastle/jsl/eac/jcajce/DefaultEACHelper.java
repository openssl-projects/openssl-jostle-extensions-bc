package org.bouncycastle.jsl.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.jsl.jcajce.util.DefaultProviderName;

class DefaultEACHelper
    implements EACHelper
{
    public KeyFactory createKeyFactory(String type)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? KeyFactory.getInstance(type)
            : KeyFactory.getInstance(type, providerName);
    }
}
