package org.bouncycastle.jsl.cms.jcajce;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsl.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.SymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.jcajce.JceAsymmetricKeyUnwrapper;
import org.bouncycastle.jsl.operator.jcajce.JceKTSKeyUnwrapper;

interface JcaJceExtHelper
    extends JcaJceHelper
{
    JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey);

    JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo);

    SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey);

    AsymmetricKeyUnwrapper createKEMUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey);
}
