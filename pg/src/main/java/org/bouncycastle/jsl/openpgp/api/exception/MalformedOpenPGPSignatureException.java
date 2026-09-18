package org.bouncycastle.jsl.openpgp.api.exception;

import org.bouncycastle.jsl.openpgp.api.OpenPGPSignature;

/**
 * An OpenPGP Signature is malformed (missing required subpackets, etc.).
 */
public class MalformedOpenPGPSignatureException
        extends OpenPGPSignatureException
{

    public MalformedOpenPGPSignatureException(OpenPGPSignature signature, String message)
    {
        super(signature, message);
    }
}
