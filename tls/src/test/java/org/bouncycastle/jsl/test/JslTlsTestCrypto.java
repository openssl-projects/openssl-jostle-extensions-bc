package org.bouncycastle.jsl.test;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jsl.tls.NamedGroup;
import org.bouncycastle.jsl.tls.crypto.TlsCrypto;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.openssl.jostle.jcajce.spec.ChaCha20CounterParameterSpec;

/**
 * The TlsCrypto the ported bc-java tests run on. Upstream's tests build the lightweight BcTlsCrypto,
 * which this library does not carry; here it is the JCA crypto over the provider under test.
 */
public final class JslTlsTestCrypto
{
    private JslTlsTestCrypto()
    {
    }

    public static JcaTlsCrypto create()
    {
        return create(new SecureRandom());
    }

    public static JcaTlsCrypto create(SecureRandom random)
    {
        return new JcaTlsCryptoProvider().setProvider(JslTestProvider.install()).create(random);
    }

    /**
     * Whether the crypto serves a named group. A hybrid group needs both halves, which a FIPS module
     * serves independently. Prints the skip line when it does not, so the caller can return early.
     */
    public static boolean supportsGroup(TlsCrypto crypto, int namedGroup)
    {
        boolean supported = NamedGroup.refersToASpecificHybrid(namedGroup)
            ? crypto.hasNamedGroup(NamedGroup.getHybridFirst(namedGroup))
                && crypto.hasNamedGroup(NamedGroup.getHybridSecond(namedGroup))
            : crypto.hasNamedGroup(namedGroup);

        if (!supported)
        {
            System.out.println("[skipped] unsupported group " + NamedGroup.getText(namedGroup));
        }
        return supported;
    }

    /**
     * Whether the provider can compute the DTLS 1.3 record number mask for ChaCha20-Poly1305 (RFC 9147
     * 4.2.3): a ChaCha20 cipher started on a block counter, asked for the way the library asks. A FIPS
     * module serves no ChaCha20 at all.
     */
    public static boolean canMaskChaCha20()
    {
        try
        {
            Cipher cipher = Cipher.getInstance("ChaCha20", JslTestProvider.install());
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[32], "ChaCha20"),
                new ChaCha20CounterParameterSpec(new byte[12], 7));
            return cipher.doFinal(new byte[16]).length == 16;
        }
        catch (Exception e)
        {
            return false;
        }
    }
}
