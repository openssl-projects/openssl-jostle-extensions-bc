package org.bouncycastle.jsl.cms;

import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;

public abstract class AbstractKeyAgreeRecipient
    extends AbstractRecipient
    implements KeyAgreeRecipient
{
    protected boolean isEC(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isEC(algorithmOID);
    }

    protected boolean isMQV(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isMQV(algorithmOID);
    }

    protected boolean isRFC2631(ASN1ObjectIdentifier algorithmOID)
    {
        return CMSUtils.isRFC2631(algorithmOID);
    }
}
