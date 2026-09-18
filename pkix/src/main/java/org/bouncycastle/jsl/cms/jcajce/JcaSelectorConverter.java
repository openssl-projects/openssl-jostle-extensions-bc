package org.bouncycastle.jsl.cms.jcajce;

import java.io.IOException;
import java.security.cert.X509CertSelector;

import org.bouncycastle.jsl.asn1.ASN1OctetString;
import org.bouncycastle.jsl.asn1.x500.X500Name;
import org.bouncycastle.jsl.cms.KeyTransRecipientId;
import org.bouncycastle.jsl.cms.SignerId;
import org.bouncycastle.jsl.util.Exceptions;

public class JcaSelectorConverter
{
    public JcaSelectorConverter()
    {

    }

    public SignerId getSignerId(X509CertSelector certSelector)
    {
        try
        {
            if (certSelector.getSubjectKeyIdentifier() != null)
            {
                return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
            }
            else
            {
                return new SignerId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
            }
        }
        catch (IOException e)
        {
            throw Exceptions.illegalArgumentException("unable to convert issuer", e);
        }
    }

    public KeyTransRecipientId getKeyTransRecipientId(X509CertSelector certSelector)
    {
        try
        {
            if (certSelector.getSubjectKeyIdentifier() != null)
            {
                return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber(), ASN1OctetString.getInstance(certSelector.getSubjectKeyIdentifier()).getOctets());
            }
            else
            {
                return new KeyTransRecipientId(X500Name.getInstance(certSelector.getIssuerAsBytes()), certSelector.getSerialNumber());
            }
        }
        catch (IOException e)
        {
            throw Exceptions.illegalArgumentException("unable to convert issuer", e);
        }
    }
}
