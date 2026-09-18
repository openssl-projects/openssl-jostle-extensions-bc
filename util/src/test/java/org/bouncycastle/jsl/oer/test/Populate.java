package org.bouncycastle.jsl.oer.test;

import org.bouncycastle.jsl.asn1.ASN1Encodable;

public interface Populate
{
    boolean isFinished(int tick);
    ASN1Encodable populate(int tick, ASN1Encodable[] priorValues);
}
