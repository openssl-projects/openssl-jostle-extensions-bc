package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPPrivateKey;

/**
 * Builder for {@link PGPContentSigner} objects.
 * The purpose of this class is to act as an abstract factory, whose subclasses can decide, which concrete
 * implementation to use for the {@link PGPContentSigner}.
 */
public interface PGPContentSignerBuilder
{
    PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey)
        throws PGPException;
}
