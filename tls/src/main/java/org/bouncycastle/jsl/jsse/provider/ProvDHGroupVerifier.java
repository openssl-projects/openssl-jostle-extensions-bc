package org.bouncycastle.jsl.jsse.provider;

import org.bouncycastle.jsl.tls.DefaultTlsDHGroupVerifier;
import org.bouncycastle.jsl.tls.crypto.DHGroup;

class ProvDHGroupVerifier
    extends DefaultTlsDHGroupVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("org.bouncycastle.jsl.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("org.bouncycastle.jsl.jsse.client.dh.unrestrictedGroups", false);

    ProvDHGroupVerifier()
    {
        super(provMinimumPrimeBits);
    }

    @Override
    protected boolean checkGroup(DHGroup dhGroup)
    {
        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
