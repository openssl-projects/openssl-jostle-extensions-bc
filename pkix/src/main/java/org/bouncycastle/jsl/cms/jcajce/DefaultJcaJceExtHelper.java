package org.bouncycastle.jsl.cms.jcajce;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jsl.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.SymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.jcajce.JceAsymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.jcajce.JceKTSKeyUnwrapper;
import org.bouncycastle.jsl.operator.jcajce.JceSymmetricKeyUnwrapper;

class DefaultJcaJceExtHelper
    extends DefaultJcaJceHelper
    implements JcaJceExtHelper
{
    public JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
    {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
    }

    public JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo)
    {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo);
    }

    public SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey)
    {
        return new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
    }

    public AsymmetricKeyUnwrapper createKEMUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey)
    {
        return new JceCMSKEMKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey);
    }
}
