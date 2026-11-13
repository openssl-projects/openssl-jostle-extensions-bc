package org.bouncycastle.jsl.openpgp.api.operator;

import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.operator.PGPContentSignerBuilderProvider;

public interface PGPContentSignerBuilderProviderFactory
{
    PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            KeyPassphraseProvider keyPassphraseProvider,
            int hashAlgorithmId)
            throws PGPException;
}
