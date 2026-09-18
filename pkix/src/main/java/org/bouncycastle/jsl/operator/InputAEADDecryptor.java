package org.bouncycastle.jsl.operator;


/**
 * Base interface for an input consuming AEAD Decryptor supporting associated text.
 */
public interface InputAEADDecryptor
    extends InputDecryptor, AADProcessor
{
}
