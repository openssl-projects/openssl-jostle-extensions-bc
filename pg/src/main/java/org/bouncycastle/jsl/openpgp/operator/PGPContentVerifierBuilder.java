package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPPublicKey;

public interface PGPContentVerifierBuilder
{
    PGPContentVerifier build(final PGPPublicKey publicKey)
        throws PGPException;
}
