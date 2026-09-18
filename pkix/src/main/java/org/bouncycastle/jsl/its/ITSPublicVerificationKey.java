package org.bouncycastle.jsl.its;

import org.bouncycastle.jsl.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;

public class ITSPublicVerificationKey
{
    protected final PublicVerificationKey verificationKey;

    public ITSPublicVerificationKey(PublicVerificationKey encryptionKey)
    {
        this.verificationKey = encryptionKey;
    }

    public PublicVerificationKey toASN1Structure()
    {
        return verificationKey;
    }
}
