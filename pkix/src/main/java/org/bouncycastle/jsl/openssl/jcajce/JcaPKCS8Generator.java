package org.bouncycastle.jsl.openssl.jcajce;

import java.security.PrivateKey;

import org.bouncycastle.jsl.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jsl.openssl.PKCS8Generator;
import org.bouncycastle.jsl.operator.OutputEncryptor;
import org.bouncycastle.jsl.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
