package org.bouncycastle.jsl.openpgp.api.exception;

import org.bouncycastle.jsl.openpgp.PGPSignatureException;
import org.bouncycastle.jsl.openpgp.api.OpenPGPSignature;

public class OpenPGPSignatureException
        extends PGPSignatureException
{
    private final OpenPGPSignature signature;

    public OpenPGPSignatureException(OpenPGPSignature signature, String message)
    {
        super(message);
        this.signature = signature;
    }

    public OpenPGPSignature getSignature()
    {
        return signature;
    }
}
