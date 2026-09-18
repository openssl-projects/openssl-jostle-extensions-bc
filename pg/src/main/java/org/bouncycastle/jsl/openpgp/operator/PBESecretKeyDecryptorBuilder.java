package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.openpgp.PGPException;

public interface PBESecretKeyDecryptorBuilder
{
    PBESecretKeyDecryptor build(char[] passphrase)
            throws PGPException;
}
