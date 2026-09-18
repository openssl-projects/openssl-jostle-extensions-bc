package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.bcpg.ContainedPacket;
import org.bouncycastle.jsl.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPException;

/**
 * An encryption method that can be applied to encrypt data in a {@link PGPEncryptedDataGenerator}.
 */
public interface PGPKeyEncryptionMethodGenerator
{

    ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey)
        throws PGPException;
}
