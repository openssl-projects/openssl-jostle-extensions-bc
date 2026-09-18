package org.bouncycastle.jsl.cert.path.validations;

import org.bouncycastle.jsl.asn1.x509.Extension;
import org.bouncycastle.jsl.asn1.x509.KeyUsage;
import org.bouncycastle.jsl.cert.X509CertificateHolder;
import org.bouncycastle.jsl.cert.path.CertPathValidation;
import org.bouncycastle.jsl.cert.path.CertPathValidationContext;
import org.bouncycastle.jsl.cert.path.CertPathValidationException;
import org.bouncycastle.jsl.util.Memoable;

public class KeyUsageValidation
    implements CertPathValidation
{
    private boolean          isMandatory;

    public KeyUsageValidation()
    {
        this(true);
    }

    public KeyUsageValidation(boolean isMandatory)
    {
        this.isMandatory = isMandatory;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        context.addHandledExtension(Extension.keyUsage);

        if (!context.isEndEntity())
        {
            KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());

            if (usage != null)
            {
                if (!usage.hasUsages(KeyUsage.keyCertSign))
                {
                    throw new CertPathValidationException("Issuer certificate KeyUsage extension does not permit key signing");
                }
            }
            else
            {
                if (isMandatory)
                {
                    throw new CertPathValidationException("KeyUsage extension not present in CA certificate");
                }
            }
        }
    }

    public Memoable copy()
    {
        return new KeyUsageValidation(isMandatory);
    }

    public void reset(Memoable other)
    {
        KeyUsageValidation v = (KeyUsageValidation)other;

        this.isMandatory = v.isMandatory;
    }
}
