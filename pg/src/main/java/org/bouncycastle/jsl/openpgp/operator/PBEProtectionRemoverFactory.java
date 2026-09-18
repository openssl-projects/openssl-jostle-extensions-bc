package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.openpgp.PGPException;

public interface PBEProtectionRemoverFactory
{
    PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException;
}
