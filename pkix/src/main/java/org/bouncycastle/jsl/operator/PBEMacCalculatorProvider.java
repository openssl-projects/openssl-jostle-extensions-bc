package org.bouncycastle.jsl.operator;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;

public interface PBEMacCalculatorProvider
{
    MacCalculator get(AlgorithmIdentifier algorithm, char[] password)
        throws OperatorCreationException;
}
