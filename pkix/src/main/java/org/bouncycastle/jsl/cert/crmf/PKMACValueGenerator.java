package org.bouncycastle.jsl.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.jsl.asn1.ASN1Encoding;
import org.bouncycastle.jsl.asn1.DERBitString;
import org.bouncycastle.jsl.asn1.crmf.PKMACValue;
import org.bouncycastle.jsl.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jsl.operator.MacCalculator;

abstract class PKMACValueGenerator
{
    private PKMACValueGenerator()
    {
    }

    public static PKMACValue generate(PKMACBuilder builder, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        MacCalculator calculator = builder.build(password);

        OutputStream macOut = calculator.getOutputStream();

        try
        {
            macOut.write(keyInfo.getEncoded(ASN1Encoding.DER));

            macOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.getMessage(), e);
        }

        return new PKMACValue(calculator.getAlgorithmIdentifier(), new DERBitString(calculator.getMac()));
    }
}
