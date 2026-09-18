package org.bouncycastle.jsl.crypto.util;

import java.io.IOException;

import org.bouncycastle.jsl.asn1.ASN1OctetString;
import org.bouncycastle.jsl.asn1.ASN1Primitive;
import org.bouncycastle.jsl.asn1.DEROctetString;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Exceptions;

class DerUtil
{
    static ASN1OctetString getOctetString(byte[] data)
    {
        if (data == null)
        {
            return new DEROctetString(new byte[0]);
        }

        return new DEROctetString(Arrays.clone(data));
    }

    static byte[] toByteArray(ASN1Primitive primitive)
    {
        try
        {
            return primitive.getEncoded();
        }
        catch (final IOException e)
        {
            throw Exceptions.illegalStateException("Cannot get encoding: " + e.getMessage(), e);
        }
    }
}
