package org.bouncycastle.jsl.openpgp.operator;

import org.bouncycastle.jsl.openpgp.PGPException;

public interface PGPExternalContentSignerBuilder
        extends PGPContentSignerBuilder
{

    /**
     * Builder a {@link PGPContentSigner} using an OpenPGP key with private key material held
     * externally - e.g. by a smart card.
     *
     * @param signatureType signature type
     * @return content signer
     * @throws PGPException cannot sign
     */
    PGPContentSigner build(final int signatureType)
            throws PGPException;
}
