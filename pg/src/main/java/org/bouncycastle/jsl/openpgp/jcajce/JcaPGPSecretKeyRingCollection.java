package org.bouncycastle.jsl.openpgp.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.PGPSecretKeyRing;
import org.bouncycastle.jsl.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class JcaPGPSecretKeyRingCollection
    extends PGPSecretKeyRingCollection
{
    public JcaPGPSecretKeyRingCollection(byte[] encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }

    public JcaPGPSecretKeyRingCollection(InputStream in)
        throws IOException, PGPException
    {
        super(in, new JcaKeyFingerprintCalculator());
    }

    public JcaPGPSecretKeyRingCollection(Collection<PGPSecretKeyRing> collection)
    {
        super(collection);
    }
}
