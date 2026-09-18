package org.bouncycastle.jsl.tls.crypto.impl.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.jsl.tls.SignatureAlgorithm;

public class JcaTlsEd25519Signer
    extends JcaTlsEdDSASigner
{
    public JcaTlsEd25519Signer(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        super(crypto, privateKey, SignatureAlgorithm.ed25519, "Ed25519");
    }
}
