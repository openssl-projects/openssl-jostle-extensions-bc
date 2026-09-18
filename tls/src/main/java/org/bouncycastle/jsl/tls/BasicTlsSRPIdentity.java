package org.bouncycastle.jsl.tls;

import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;

/**
 * A basic SRP Identity holder.
 */
public class BasicTlsSRPIdentity
    implements TlsSRPIdentity
{
    protected byte[] identity;
    protected byte[] password;

    public BasicTlsSRPIdentity(byte[] identity, byte[] password)
    {
        this.identity = Arrays.clone(identity);
        this.password = Arrays.clone(password);
    }

    public BasicTlsSRPIdentity(String identity, String password)
    {
        this.identity = Strings.toUTF8ByteArray(identity);
        this.password = Strings.toUTF8ByteArray(password);
    }

    public byte[] getSRPIdentity()
    {
        return identity;
    }

    public byte[] getSRPPassword()
    {
        return password;
    }
}
