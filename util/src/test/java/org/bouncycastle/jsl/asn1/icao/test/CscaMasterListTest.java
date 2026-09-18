package org.bouncycastle.jsl.asn1.icao.test;

import java.io.IOException;

import org.bouncycastle.jsl.asn1.ASN1Primitive;
import org.bouncycastle.jsl.asn1.icao.CscaMasterList;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.io.Streams;
import org.bouncycastle.jsl.util.test.SimpleTest;

public class CscaMasterListTest
    extends SimpleTest
{
    @org.junit.Test
    public void test() throws Exception {
        org.bouncycastle.jsl.util.test.TestResult result = perform();
        if (!result.isSuccessful()) { throw new junit.framework.AssertionFailedError(result.toString()); }
    }

    public String getName()
    {
        return "CscaMasterList";
    }

    public void performTest()
        throws Exception
    {
        byte[] input = getInput("masterlist-content.data");
        CscaMasterList parsedList
            = CscaMasterList.getInstance(ASN1Primitive.fromByteArray(input));

        if (parsedList.getCertStructs().length != 3)
        {
            fail("Cert structure parsing failed: incorrect length");
        }

        byte[] output = parsedList.getEncoded();
        if (!Arrays.areEqual(input, output))
        {
            fail("Encoding failed after parse");
        }
    }

    private byte[] getInput(String name)
        throws IOException
    {
        return Streams.readAll(getClass().getResourceAsStream(name));
    }

    public static void main(
        String[] args)
    {
        runTest(new CscaMasterListTest());
    }
}
