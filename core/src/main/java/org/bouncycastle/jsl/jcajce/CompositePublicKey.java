package org.bouncycastle.jsl.jcajce;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A public key made of component public keys, in a fixed order.
 * <p>
 * This is a reduced form of bc-java's class of the same name. Upstream's class also encodes itself
 * as a composite SubjectPublicKeyInfo through the BouncyCastle provider's key factories, which this
 * library does not carry. Here it is a container only: it has no encoding, and the components are
 * keys of whichever provider made them.
 * </p>
 */
public class CompositePublicKey
    implements PublicKey
{
    private final List<PublicKey> keys;

    /**
     * Create a composite public key from its components.
     *
     * @param keys the component keys, in order.
     */
    public CompositePublicKey(PublicKey... keys)
    {
        if (keys == null || keys.length == 0)
        {
            throw new IllegalArgumentException(
                "at least one public key must be provided for the composite public key");
        }

        List<PublicKey> keyList = new ArrayList<PublicKey>(keys.length);
        for (int i = 0; i != keys.length; i++)
        {
            keyList.add(keys[i]);
        }
        this.keys = Collections.unmodifiableList(keyList);
    }

    /**
     * Return the component keys.
     *
     * @return an immutable list of the component keys, in order.
     */
    public List<PublicKey> getPublicKeys()
    {
        return keys;
    }

    public String getAlgorithm()
    {
        return "Composite";
    }

    /**
     * @return null: this container has no encoding of its own.
     */
    public String getFormat()
    {
        return null;
    }

    /**
     * @return null: this container has no encoding of its own.
     */
    public byte[] getEncoded()
    {
        return null;
    }

    public int hashCode()
    {
        return keys.hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof CompositePublicKey)
        {
            return keys.equals(((CompositePublicKey)o).keys);
        }

        return false;
    }
}
