package org.bouncycastle.jsl.asn1.misc;

import org.bouncycastle.jsl.asn1.ASN1IA5String;
import org.bouncycastle.jsl.asn1.DERIA5String;

public class NetscapeRevocationURL
    extends DERIA5String
{
    public NetscapeRevocationURL(
        ASN1IA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "NetscapeRevocationURL: " + this.getString();
    }
}
