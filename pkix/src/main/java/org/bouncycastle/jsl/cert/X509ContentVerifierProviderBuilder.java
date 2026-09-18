package org.bouncycastle.jsl.cert;

import org.bouncycastle.jsl.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jsl.operator.ContentVerifierProvider;
import org.bouncycastle.jsl.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder
{
    ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
        throws OperatorCreationException;

    ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
        throws OperatorCreationException;
}
