package org.bouncycastle.jsl.cms;

import org.bouncycastle.jsl.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
