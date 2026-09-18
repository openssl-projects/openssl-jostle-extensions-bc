package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import org.bouncycastle.jsl.tls.HashAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAlgorithm;
import org.bouncycastle.jsl.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.jsl.util.Strings;

class JcaUtils
{
    static String getJcaAlgorithmName(SignatureAndHashAlgorithm algorithm)
    {
        return (HashAlgorithm.getName(algorithm.getHash()) + "WITH"
            + Strings.toUpperCase(SignatureAlgorithm.getName(algorithm.getSignature())));
    }
}
