package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.bcpg.PublicKeyPacket;
import org.bouncycastle.jsl.openpgp.PGPException;

public interface KeyFingerPrintCalculator
{
    byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException;
}
