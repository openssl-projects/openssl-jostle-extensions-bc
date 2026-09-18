package org.bouncycastle.jsl.asn1;

public class DERVideotexString
    extends ASN1VideotexString
{
    public DERVideotexString(byte[] octets)
    {
        this(octets, true);
    }

    DERVideotexString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
