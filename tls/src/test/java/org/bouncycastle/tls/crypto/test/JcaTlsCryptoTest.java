package org.bouncycastle.tls.crypto.test;

import java.security.SecureRandom;
import java.security.Security;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class JcaTlsCryptoTest
    extends TlsCryptoTest
{
    static
    {
        // testSignatures13 decodes ML-DSA/SLH-DSA/EdDSA certificate keys via a CertificateFactory,
        // which resolves the SPKI to a PublicKey through the installed providers. JSL must be
        // registered (not merely passed to setProvider) so those keys decode to JSL types with the
        // FIPS-conformant encoding the TLS layer's certificate checks expect.
        Security.addProvider(new JostleProvider());
    }

    public JcaTlsCryptoTest()
    {
        super(new JcaTlsCryptoProvider().setProvider(new JostleProvider()).create(new SecureRandom()));
    }
}
