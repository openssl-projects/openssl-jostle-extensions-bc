package org.bouncycastle.jsl.oer.its.etsi102941;

import org.bouncycastle.jsl.asn1.ASN1Sequence;
import org.bouncycastle.jsl.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.jsl.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class CertificateRevocationListMessage
    extends EtsiTs103097DataSigned
{

    public CertificateRevocationListMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected CertificateRevocationListMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static CertificateRevocationListMessage getInstance(Object o)
    {
        if (o instanceof CertificateRevocationListMessage)
        {
            return (CertificateRevocationListMessage)o;
        }
        if (o != null)
        {
            return new CertificateRevocationListMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
