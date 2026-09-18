package org.bouncycastle.jsl.jsse.provider.test;

import java.security.SecureRandom;

import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class FipsJcaTlsCryptoProvider extends JcaTlsCryptoProvider
{
    @Override
    public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom)
    {
        return new FipsJcaTlsCrypto(getHelper(), getAltHelper(), keyRandom, nonceRandom);
    }
}
