package org.bouncycastle.jsl.cms;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.operator.AsymmetricKeyWrapper;

public abstract class KEMKeyWrapper
    extends AsymmetricKeyWrapper
{
    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        super(algorithmId);
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();

    public abstract byte[] getUkm();
}
