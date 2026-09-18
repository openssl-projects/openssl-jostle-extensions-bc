package org.bouncycastle.jsl.bcpg.sig;

import org.bouncycastle.jsl.bcpg.SignatureSubpacket;
import org.bouncycastle.jsl.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket for embedding one Signature into another.
 * This packet is used e.g. for embedding a primary-key binding signature
 * ({@link org.bouncycastle.jsl.openpgp.PGPSignature#PRIMARYKEY_BINDING}) into a subkey-binding signature
 * ({@link org.bouncycastle.jsl.openpgp.PGPSignature#SUBKEY_BINDING}) for a signing-capable subkey.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.26">
 *     RFC4880 - Embedded Signature</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-embedded-signature">
 *     RFC9580 - Embedded Signature</a>
 */
public class EmbeddedSignature
    extends SignatureSubpacket
{
    public EmbeddedSignature(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.EMBEDDED_SIGNATURE, critical, isLongLength, data);
    }
}