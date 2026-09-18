package org.bouncycastle.jsl.openpgp.operator.jcajce;

import java.security.Provider;

import org.bouncycastle.jsl.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jsl.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jsl.jcajce.util.ProviderJcaJceHelper;

class OperatorUtils
{
    static OperatorHelper createDefaultHelper()
    {
        return new OperatorHelper(new DefaultJcaJceHelper());
    }

    static OperatorHelper createProviderHelper(Provider provider)
    {
        return new OperatorHelper(new ProviderJcaJceHelper(provider));
    }

    static OperatorHelper createNamedHelper(String providerName)
    {
        return new OperatorHelper(new NamedJcaJceHelper(providerName));
    }
}
