package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jsl.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsl.tls.AlertDescription;
import org.bouncycastle.jsl.tls.TlsFatalAlert;
import org.bouncycastle.jsl.tls.crypto.impl.TlsRecordNumberMask;
import org.bouncycastle.jsl.util.Pack;
import org.openssl.jostle.jcajce.spec.ChaCha20CounterParameterSpec;

/**
 * RFC 9147 4.2.3: Mask = ChaCha20(sn_key, Ciphertext[0..3], Ciphertext[4..15]).
 * <p>
 * Upstream computes this with its lightweight ChaCha20 engine. This library implements no primitive,
 * so the mask comes from the provider's "ChaCha20" cipher, started on the block counter with the
 * provider's nonce-and-counter spec. That spec is accepted on every Java version, so the mask does
 * not depend on {@code javax.crypto.spec.ChaCha20ParameterSpec}, which is Java 11 and later.
 * </p>
 */
public class JceChaCha20RecordNumberMask
    implements TlsRecordNumberMask
{
    private static final byte[] ZEROES = new byte[16];

    private final JcaJceHelper helper;

    private Cipher cipher;
    private SecretKey key;

    public JceChaCha20RecordNumberMask(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public void setKey(byte[] key, int keyOff, int keyLen) throws IOException
    {
        try
        {
            if (null == cipher)
            {
                cipher = helper.createCipher("ChaCha20");
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "no ChaCha20 cipher for the DTLS 1.3 record number mask", e);
        }

        this.key = new SecretKeySpec(key, keyOff, keyLen, "ChaCha20");
    }

    public void generateMask(byte[] ciphertext, int ciphertextOff, byte[] mask, int maskOff) throws IOException
    {
        if (null == key)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        try
        {
            int counter = Pack.littleEndianToInt(ciphertext, ciphertextOff);

            byte[] nonce = new byte[12];
            System.arraycopy(ciphertext, ciphertextOff + 4, nonce, 0, 12);

            // A stream cipher runs the same way in both directions. Decrypt mode avoids a provider's
            // refusal to encrypt twice under one key and nonce, which a repeated record would trip.
            cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20CounterParameterSpec(nonce, counter));

            if (16 != cipher.doFinal(ZEROES, 0, 16, mask, maskOff))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                "the provider cannot position ChaCha20 on a block counter for the DTLS 1.3 record number mask", e);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}
