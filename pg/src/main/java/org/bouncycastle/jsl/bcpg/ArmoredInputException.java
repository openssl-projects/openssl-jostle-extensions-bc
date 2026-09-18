package org.bouncycastle.jsl.bcpg;

import java.io.IOException;

public class ArmoredInputException
    extends IOException
{
    public ArmoredInputException(String msg)
    {
        super(msg);
    }
}
