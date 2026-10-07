package org.bouncycastle.jsl.openpgp.test;

import junit.framework.TestCase;
import org.bouncycastle.jsl.bcpg.ArmoredOutputStream;
import org.bouncycastle.jsl.bcpg.PacketFormat;
import org.bouncycastle.jsl.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKeyReader;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Armored output must come back as UTF-8, whatever the platform charset.
 */
public class ArmorCharsetTest
    extends TestCase
{
    // U+201D is E2 80 9D in UTF-8; windows-1252 leaves 0x9D undefined, so a 1252 decode cannot round-trip.
    private static final String COMMENT = "Gr\u00fc\u00dfe \u201d \u65e5\u672c";

    private static OpenPGPCertificate certificate()
        throws Exception
    {
        JslTestProvider.install();
        return new OpenPGPKeyReader().parseCertificate(new ArmoredOutputStreamTest().publicKey);
    }

    private static ArmoredOutputStream.Builder armor()
    {
        return ArmoredOutputStream.builder().clearHeaders().addComment(COMMENT);
    }

    public void testCertificateArmorKeepsANonAsciiComment()
        throws Exception
    {
        String armored = certificate().toAsciiArmoredString(PacketFormat.ROUNDTRIP, armor());

        assertTrue(armored, armored.contains("Comment: " + COMMENT));
    }

    public void testSignatureArmorKeepsANonAsciiComment()
        throws Exception
    {
        String armored = certificate().getPrimaryKey().getLatestSelfSignature()
            .toAsciiArmoredString(PacketFormat.ROUNDTRIP, armor());

        assertTrue(armored, armored.contains("Comment: " + COMMENT));
    }
}
