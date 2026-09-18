package org.bouncycastle.jsl.oer.test;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.jsl.util.encoders.Hex;

public class PrintingInputStream
    extends InputStream
{
    private final InputStream src;

    public PrintingInputStream(InputStream src)
    {
        this.src = src;
    }

    public int read()
        throws IOException
    {
        int s = src.read();
        System.out.print(Hex.toHexString(new byte[]{(byte)(s & 0xFF)}));
        return s;
    }
}
