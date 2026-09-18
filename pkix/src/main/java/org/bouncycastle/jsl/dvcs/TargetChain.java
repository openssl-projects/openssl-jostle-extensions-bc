package org.bouncycastle.jsl.dvcs;

import org.bouncycastle.jsl.asn1.dvcs.TargetEtcChain;

public class TargetChain
{
    private final TargetEtcChain certs;

    public TargetChain(TargetEtcChain certs)
    {
        this.certs = certs;
    }

    public TargetEtcChain toASN1Structure()
    {
        return certs;
    }
}
