package org.bouncycastle.jsl.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * OpenPGP v6 (SEIPD v2) AEAD password-based encrypt/decrypt round-trip through JSL. Exercises the
 * AEAD HKDF-SHA256 key derivations on the JSL operator path: the v6 SKESK KEK derivation
 * ({@code JcePBEKeyEncryptionMethodGenerator}/{@code JcePBEDataDecryptorFactoryBuilder} →
 * {@code JceAEADUtil.generateHKDFBytes}) and the message-key/IV derivation on decrypt
 * ({@code JceAEADUtil.deriveMessageKeyAndIv}) — the sites aligned onto JSL's native HKDF.
 */
public class PgpV6AeadPbeRoundTripTest
{
    private static final char[] PASSWORD = "Rabbit".toCharArray();

    @BeforeClass
    public static void installProvider()
        throws Exception
    {
        if (Security.getProvider("JSL") == null)
        {
            Class<?> c = Class.forName("org.openssl.jostle.jcajce.provider.JostleProvider");
            Security.addProvider((Provider)c.getDeclaredConstructor().newInstance());
        }
    }

    @Test
    public void v6AeadOcbPbeRoundTrip()
        throws Exception
    {
        byte[] data = "OpenPGP v6 AEAD over an HKDF-derived key, through OpenSSL".getBytes("UTF-8");

        PGPDigestCalculatorProvider digCalcProv =
            new JcaPGPDigestCalculatorProviderBuilder().setProvider("JSL").build();

        JcePGPDataEncryptorBuilder encBuilder =
            new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setProvider("JSL");
        encBuilder.setUseV6AEAD();
        encBuilder.setWithAEAD(AEADAlgorithmTags.OCB, 6);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encBuilder, false);
        encGen.setForceSessionKey(true);
        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(PASSWORD,
            digCalcProv.get(HashAlgorithmTags.SHA256)).setProvider("JSL"));

        ByteArrayOutputStream ctOut = new ByteArrayOutputStream();
        OutputStream encOut = encGen.open(ctOut, new byte[1 << 9]);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(encOut, PGPLiteralData.UTF8, "", new Date(), new byte[1 << 9]);
        litOut.write(data);
        litOut.close();
        encGen.close();

        // decrypt
        PGPObjectFactory of = new JcaPGPObjectFactory(new ByteArrayInputStream(ctOut.toByteArray()));
        PGPEncryptedDataList encList = (PGPEncryptedDataList)of.nextObject();
        PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)encList.get(0);

        PBEDataDecryptorFactory decFact = new JcePBEDataDecryptorFactoryBuilder(
            new JcaPGPDigestCalculatorProviderBuilder().setProvider("JSL").build()).setProvider("JSL").build(PASSWORD);

        InputStream clear = pbe.getDataStream(decFact);
        PGPObjectFactory of2 = new JcaPGPObjectFactory(clear);
        PGPLiteralData ld = (PGPLiteralData)of2.nextObject();
        byte[] recovered = Streams.readAll(ld.getInputStream());

        assertTrue("v6 AEAD PBE content did not round-trip", Arrays.areEqual(data, recovered));
    }
}
