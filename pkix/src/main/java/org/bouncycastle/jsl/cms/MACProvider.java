package org.bouncycastle.jsl.cms;

import java.io.IOException;

interface MACProvider
{
    byte[] getMAC();

    void init() throws IOException;
}

