package org.bouncycastle.jsl.operator;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;

public interface MacCalculatorProvider
{
    public MacCalculator get(AlgorithmIdentifier algorithm);
}
