package org.bouncycastle.jsl.openpgp.operator.jcajce;

import org.bouncycastle.jsl.bcpg.AEADAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PublicKeyPacket;
import org.bouncycastle.jsl.bcpg.S2K;
import org.bouncycastle.jsl.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jsl.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.jsl.openpgp.operator.PBESecretKeyEncryptorFactory;

import java.security.Provider;

public class JcaAEADSecretKeyEncryptorFactory
        implements PBESecretKeyEncryptorFactory
{
    private JcaAEADSecretKeyEncryptorBuilder builder = new JcaAEADSecretKeyEncryptorBuilder(
            AEADAlgorithmTags.OCB,
            SymmetricKeyAlgorithmTags.AES_256,
            S2K.Argon2Params.memoryConstrainedParameters());

    public JcaAEADSecretKeyEncryptorFactory setProvider(Provider provider)
    {
        builder.setProvider(provider);
        return this;
    }

    @Override
    public PBESecretKeyEncryptor build(char[] passphrase, PublicKeyPacket pubKeyPacket)
    {
        if (passphrase == null)
        {
            return null;
        }
        return builder.build(passphrase, pubKeyPacket);
    }
}
