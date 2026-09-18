package org.bouncycastle.jsl.openpgp.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyRing;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPPublicKeyRingCollection
    extends PGPPublicKeyRingCollection
{
    public JcaPGPPublicKeyRingCollection(byte[] encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }

    public JcaPGPPublicKeyRingCollection(InputStream in)
        throws IOException, PGPException
    {
        super(in, new JcaKeyFingerprintCalculator());
    }

    public JcaPGPPublicKeyRingCollection(Collection<PGPPublicKeyRing> collection)
    {
        super(collection);
    }
}
