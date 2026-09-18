package org.bouncycastle.jsl.cert.ocsp.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jsl.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jsl.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.jsl.cert.ocsp.OCSPException;
import org.bouncycastle.jsl.operator.DigestCalculator;

public class JcaBasicOCSPRespBuilder
    extends BasicOCSPRespBuilder
{
    public JcaBasicOCSPRespBuilder(X500Principal principal)
    {
        super(new JcaRespID(principal));
    }

    public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc);
    }
}
