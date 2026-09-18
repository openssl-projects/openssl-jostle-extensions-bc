package org.bouncycastle.jsl.cert.jcajce;

import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.bouncycastle.jsl.jcajce.util.DefaultProviderName;

class DefaultCertHelper
    extends CertHelper
{
    protected CertificateFactory createCertificateFactory(String type)
        throws CertificateException, NoSuchProviderException
    {
        String providerName = DefaultProviderName.getProviderName();
        return providerName == null
            ? CertificateFactory.getInstance(type)
            : CertificateFactory.getInstance(type, providerName);
    }
}
