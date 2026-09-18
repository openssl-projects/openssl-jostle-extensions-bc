package org.bouncycastle.jsl.cert.path;

import org.bouncycastle.jsl.cert.X509CertificateHolder;
import org.bouncycastle.jsl.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
