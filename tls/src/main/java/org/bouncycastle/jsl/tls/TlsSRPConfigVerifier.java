package org.bouncycastle.jsl.tls;

import org.bouncycastle.jsl.tls.crypto.TlsSRPConfig;

/**
 * Interface for verifying SRP config needs to conform to.
 */
public interface TlsSRPConfigVerifier
{
    /**
     * Check whether the given SRP configuration is acceptable for use.
     * 
     * @param srpConfig the {@link TlsSRPConfig} to check.
     * @return true if (and only if) the specified configuration is acceptable.
     */
    boolean accept(TlsSRPConfig srpConfig);
}
