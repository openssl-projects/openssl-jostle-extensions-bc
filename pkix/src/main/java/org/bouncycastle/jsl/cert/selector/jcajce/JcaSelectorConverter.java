package org.bouncycastle.jsl.cert.selector.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import org.bouncycastle.jsl.asn1.ASN1OctetString;
import org.bouncycastle.jsl.asn1.x500.X500Name;
import org.bouncycastle.jsl.cert.selector.X509CertificateHolderSelector;
import org.bouncycastle.jsl.util.Exceptions;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public X509CertificateHolderSelector getCertificateHolderSelector(X509CertSelector certSelector)
    {
        try
        {
            X500Name issuer = X500Name.getInstance(certSelector.getIssuerAsBytes());
            BigInteger serialNumber = certSelector.getSerialNumber();
            byte[] subjectKeyId = null;

            byte[] subjectKeyIdentifier = certSelector.getSubjectKeyIdentifier();
            if (subjectKeyIdentifier != null)
            {
                subjectKeyId = ASN1OctetString.getInstance(subjectKeyIdentifier).getOctets();
            }

            return new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalArgumentException("unable to convert issuer", e);
        }
    }
}
