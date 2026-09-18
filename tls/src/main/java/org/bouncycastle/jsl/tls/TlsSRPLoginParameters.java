package org.bouncycastle.jsl.tls;

import java.math.BigInteger;

import org.bouncycastle.jsl.tls.crypto.TlsSRPConfig;
import org.bouncycastle.jsl.util.Arrays;

public class TlsSRPLoginParameters
{
    protected byte[] identity;
    protected TlsSRPConfig srpConfig;
    protected BigInteger verifier;
    protected byte[] salt;

    public TlsSRPLoginParameters(byte[] identity, TlsSRPConfig srpConfig, BigInteger verifier, byte[] salt)
    {
        this.identity = Arrays.clone(identity);
        this.srpConfig = srpConfig;
        this.verifier = verifier;
        this.salt = Arrays.clone(salt);
    }

    public TlsSRPConfig getConfig()
    {
        return srpConfig;
    }

    public byte[] getIdentity()
    {
        return identity;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public BigInteger getVerifier()
    {
        return verifier;
    }
}
