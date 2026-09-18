package org.bouncycastle.jsl.mime.smime;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.jsl.mime.BasicMimeParser;
import org.bouncycastle.jsl.mime.Headers;
import org.bouncycastle.jsl.mime.MimeParser;
import org.bouncycastle.jsl.mime.MimeParserProvider;
import org.bouncycastle.jsl.operator.DigestCalculatorProvider;

public class SMimeParserProvider
    implements MimeParserProvider
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserProvider(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public MimeParser createParser(InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            SMimeUtils.autoBuffer(source));
    }

    public MimeParser createParser(Headers headers, InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            headers, SMimeUtils.autoBuffer(source));
    }
}
