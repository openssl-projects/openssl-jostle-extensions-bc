package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.util.Strings;

class JcaUtils
{
    static String getJcaAlgorithmName(SignatureAndHashAlgorithm algorithm)
    {
        return (HashAlgorithm.getName(algorithm.getHash()) + "WITH"
            + Strings.toUpperCase(SignatureAlgorithm.getName(algorithm.getSignature())));
    }
}
