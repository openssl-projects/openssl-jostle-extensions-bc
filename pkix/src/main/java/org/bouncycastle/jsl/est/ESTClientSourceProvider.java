package org.bouncycastle.jsl.est;

import java.io.IOException;

/**
 * ESTClientSourceProvider, implementations of this are expected to return a source.
 */
public interface ESTClientSourceProvider
{
    Source makeSource(String host, int port)
        throws IOException;
}
