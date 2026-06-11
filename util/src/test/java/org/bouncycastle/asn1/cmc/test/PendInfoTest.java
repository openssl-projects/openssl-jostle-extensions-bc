package org.bouncycastle.asn1.cmc.test;

import java.util.Date;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmc.PendInfo;
import org.bouncycastle.util.test.SimpleTest;


public class PendInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PendInfoTest());
    }

    @org.junit.Test
    public void test() throws Exception {
        org.bouncycastle.util.test.TestResult result = perform();
        if (!result.isSuccessful()) { throw new junit.framework.AssertionFailedError(result.toString()); }
    }

    public String getName()
    {
        return "PendInfoTest";
    }

    public void performTest()
        throws Exception
    {
        PendInfo info = new PendInfo("".getBytes(), new ASN1GeneralizedTime(new Date()));
        byte[] b = info.getEncoded();
        PendInfo infoResult = PendInfo.getInstance(b);

        isTrue("pendToken", areEqual(info.getPendToken(), infoResult.getPendToken()));
        isEquals("pendTime", info.getPendTime(), infoResult.getPendTime());

        try
        {
            PendInfo.getInstance(new DERSequence());
            fail("Sequence length not 2");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
