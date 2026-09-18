package org.bouncycastle.jsl.openssl;

import org.bouncycastle.jsl.operator.OperatorCreationException;

public interface PEMDecryptorProvider
{
    PEMDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}
