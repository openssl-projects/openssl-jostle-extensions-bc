package org.bouncycastle.jsl.openpgp;

import java.io.IOException;

import org.bouncycastle.jsl.bcpg.BCPGInputStream;
import org.bouncycastle.jsl.bcpg.TrustPacket;
import org.bouncycastle.jsl.util.Arrays;

public class PGPTrust
{

    private final TrustPacket packet;

    public PGPTrust(TrustPacket packet)
    {
        this.packet = packet;
    }

    public PGPTrust(BCPGInputStream inputStream)
        throws IOException
    {
        this((TrustPacket) inputStream.readPacket());
    }

    public TrustPacket getPacket()
    {
        return packet;
    }

    public byte[] getLevelAndTrust()
    {
        return Arrays.clone(packet.getLevelAndTrustAmount());
    }
}
