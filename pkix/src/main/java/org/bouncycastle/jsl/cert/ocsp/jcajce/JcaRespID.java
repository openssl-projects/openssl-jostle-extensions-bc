package org.bouncycastle.jsl.cert.ocsp.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jsl.asn1.x500.X500Name;
import org.bouncycastle.jsl.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jsl.cert.ocsp.OCSPException;
import org.bouncycastle.jsl.cert.ocsp.RespID;
import org.bouncycastle.jsl.operator.DigestCalculator;

public class JcaRespID
    extends RespID
{
    public JcaRespID(X500Principal name)
    {
        super(X500Name.getInstance(name.getEncoded()));
    }

    public JcaRespID(PublicKey pubKey, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), digCalc);
    }
}
