package org.bouncycastle.jsl.asn1.cmc.test;

import org.bouncycastle.jsl.asn1.DERSequence;
import org.bouncycastle.jsl.asn1.DERUTF8String;
import org.bouncycastle.jsl.asn1.cmc.BodyPartID;
import org.bouncycastle.jsl.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.jsl.asn1.cms.ContentInfo;
import org.bouncycastle.jsl.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jsl.util.test.SimpleTest;

public class TaggedContentInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new TaggedContentInfoTest());
    }

    @org.junit.Test
    public void test() throws Exception {
        org.bouncycastle.jsl.util.test.TestResult result = perform();
        if (!result.isSuccessful()) { throw new junit.framework.AssertionFailedError(result.toString()); }
    }

    public String getName()
    {
        return "TaggedContentInfoTest";
    }

    public void performTest()
        throws Exception
    {
        TaggedContentInfo tci = new TaggedContentInfo(
            new BodyPartID(10L),
            new ContentInfo(PKCSObjectIdentifiers.pkcs_9_at_contentType, new DERUTF8String("Cats")));

        byte[] b = tci.getEncoded();

        TaggedContentInfo tciResp = TaggedContentInfo.getInstance(b);

        isEquals("bodyPartID", tci.getBodyPartID(), tciResp.getBodyPartID());
        isEquals("contentInfo", tci.getContentInfo(), tciResp.getContentInfo());

        try
        {
            TaggedContentInfo.getInstance(new DERSequence());
            fail("Sequence must be 2");
        }
        catch (Throwable t)
        {
            isEquals("Exception type", t.getClass(), IllegalArgumentException.class);
        }

    }
}
