package org.bouncycastle.jsl.test;

import org.bouncycastle.jsl.bcpg.AEADAlgorithmTags;
import org.bouncycastle.jsl.bcpg.S2K;
import org.bouncycastle.jsl.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jsl.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPImplementation;
import org.bouncycastle.jsl.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * The default OpenPGP implementation hands its builders no random unless the caller gave one. A password
 * session key generator from its Argon2 factory, with an AEAD data encryptor, must then still produce a packet
 * when generate() is called directly, without OpenPGPMessageGenerator setting a random first.
 */
public class PbeAeadWithNoRandomSetTest
{
    @Test
    public void theArgon2FactoryGeneratesAnAeadSessionKeyPacketWithNoRandomSet()
        throws Exception
    {
        JslTestProvider.install();
        JslTestProvider.assumeAlgorithm("SecretKeyFactory.ARGON2", "Cipher.AES");

        JcaOpenPGPImplementation implementation = new JcaOpenPGPImplementation(JslTestProvider.provider(), null);
        PBEKeyEncryptionMethodGenerator gen = implementation.pbeKeyEncryptionMethodGenerator(
            "a passphrase".toCharArray(), S2K.Argon2Params.memoryConstrainedParameters());
        JcePGPDataEncryptorBuilder dataEncryptor =
            (JcePGPDataEncryptorBuilder)implementation.pgpDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256);
        dataEncryptor.setWithAEAD(AEADAlgorithmTags.OCB, 6).setUseV6AEAD();

        Object packet = gen.generate(dataEncryptor, new byte[32]);

        assertTrue("a symmetric-key encrypted session key packet", packet instanceof SymmetricKeyEncSessionPacket);
    }
}
