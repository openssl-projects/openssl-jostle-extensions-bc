package org.bouncycastle.jsl.cert.path.validations;

import org.bouncycastle.jsl.cert.X509CertificateHolder;

class ValidationUtils
{
    static boolean isSelfIssued(X509CertificateHolder cert)
    {
        return cert.getSubject().equals(cert.getIssuer());
    }
}
