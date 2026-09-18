package org.bouncycastle.jsl.jsse.provider;

import java.util.Set;

interface AlgorithmDecomposer
{
    Set<String> decompose(String algorithm);
}
