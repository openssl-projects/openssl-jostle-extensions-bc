package org.bouncycastle.jsl.bcpg;

public class UnsupportedPacketVersionException
    extends RuntimeException
{
    public UnsupportedPacketVersionException(String msg)
    {
        super(msg);
    }
}
