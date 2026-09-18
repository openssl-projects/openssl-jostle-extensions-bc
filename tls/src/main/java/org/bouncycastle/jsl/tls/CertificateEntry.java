package org.bouncycastle.jsl.tls;

import java.util.Hashtable;

import org.bouncycastle.jsl.tls.crypto.TlsCertificate;

public class CertificateEntry
{
    protected final TlsCertificate certificate;
    protected final Hashtable extensions;

    public CertificateEntry(TlsCertificate certificate, Hashtable extensions)
    {
        if (null == certificate)
        {
            throw new NullPointerException("'certificate' cannot be null");
        }

        this.certificate = certificate;
        this.extensions = extensions;
    }

    public TlsCertificate getCertificate()
    {
        return certificate;
    }

    public Hashtable getExtensions()
    {
        return extensions;
    }
}
