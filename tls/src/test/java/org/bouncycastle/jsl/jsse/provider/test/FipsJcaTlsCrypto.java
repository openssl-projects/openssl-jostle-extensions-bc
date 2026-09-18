package org.bouncycastle.jsl.jsse.provider.test;

import java.security.SecureRandom;

import org.bouncycastle.jsl.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsl.tls.crypto.impl.AEADNonceGeneratorFactory;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.jsl.tls.test.TestAEADGeneratorFactory;

public class FipsJcaTlsCrypto extends JcaTlsCrypto
{
    public FipsJcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)
    {
        super(helper, entropySource, nonceEntropySource);
    }

    public FipsJcaTlsCrypto(JcaJceHelper helper, JcaJceHelper altHelper, SecureRandom entropySource,
        SecureRandom nonceEntropySource)
    {
        super(helper, altHelper, entropySource, nonceEntropySource);
    }

    @Override
    public AEADNonceGeneratorFactory getFipsGCMNonceGeneratorFactory()
    {
        return FipsTestUtils.enableGCMCiphersIn12 ? TestAEADGeneratorFactory.INSTANCE : null;
    }
}
