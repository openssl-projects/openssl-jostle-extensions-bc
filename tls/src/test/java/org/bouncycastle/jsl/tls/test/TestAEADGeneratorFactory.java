package org.bouncycastle.jsl.tls.test;

import org.bouncycastle.jsl.tls.crypto.impl.AEADNonceGenerator;
import org.bouncycastle.jsl.tls.crypto.impl.AEADNonceGeneratorFactory;

public class TestAEADGeneratorFactory
    implements AEADNonceGeneratorFactory
{
    public static final AEADNonceGeneratorFactory INSTANCE = new TestAEADGeneratorFactory();

    private TestAEADGeneratorFactory()
    {
        // no op
    }

    public AEADNonceGenerator create(byte[] baseNonce, int counterSizeInBits)
    {
        return new TestAEADNonceGenerator(baseNonce, counterSizeInBits);
    }
}
