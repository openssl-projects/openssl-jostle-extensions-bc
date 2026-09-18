package org.bouncycastle.jsl.openpgp;

/**
 * Thrown if the key checksum is invalid.
 */
public class PGPKeyValidationException 
    extends PGPException
{
    /**
     * @param message
     */
    public PGPKeyValidationException(String message)
    {
        super(message);
    }
}
