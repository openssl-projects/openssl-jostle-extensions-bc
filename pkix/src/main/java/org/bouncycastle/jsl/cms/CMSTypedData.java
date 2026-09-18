package org.bouncycastle.jsl.cms;

import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;

public interface CMSTypedData
    extends CMSProcessable
{
    ASN1ObjectIdentifier getContentType();
}
