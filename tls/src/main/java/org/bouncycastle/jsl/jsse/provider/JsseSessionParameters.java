package org.bouncycastle.jsl.jsse.provider;

import org.bouncycastle.jsl.jsse.BCSNIServerName;

class JsseSessionParameters
{
    private final String endpointIDAlgorithm;
    private final BCSNIServerName matchedSNIServerName;

    JsseSessionParameters(String endpointIDAlgorithm, BCSNIServerName matchedSNIServerName)
    {
        this.endpointIDAlgorithm = endpointIDAlgorithm;
        this.matchedSNIServerName = matchedSNIServerName;
    }

    public String getEndpointIDAlgorithm()
    {
        return endpointIDAlgorithm;
    }

    public BCSNIServerName getMatchedSNIServerName()
    {
        return matchedSNIServerName;
    }
}
