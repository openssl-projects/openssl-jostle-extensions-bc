package org.bouncycastle.jsl.cms;

import java.io.OutputStream;

interface CMSSecureReadableWithAAD
    extends CMSSecureReadable
{
    void setAADStream(OutputStream stream);

    OutputStream getAADStream();

    byte[] getMAC();
}
