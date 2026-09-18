package org.bouncycastle.jsl.eac.operator.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

import org.bouncycastle.jsl.jcajce.util.DefaultProviderName;

class DefaultEACHelper
    extends EACHelper
{
    protected Signature createSignature(String type)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? Signature.getInstance(type)
            : Signature.getInstance(type, providerName);
    }
}
