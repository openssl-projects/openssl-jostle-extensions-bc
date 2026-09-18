package org.bouncycastle.jsl.its;

import org.bouncycastle.jsl.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;

public interface ETSIKeyWrapper
{
    EncryptedDataEncryptionKey wrap(byte[] secretKey);
}
