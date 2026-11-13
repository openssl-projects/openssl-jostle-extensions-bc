package org.bouncycastle.jsl.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.jsl.bcpg.ArmoredInputStream;
import org.bouncycastle.jsl.bcpg.BCPGInputStream;
import org.bouncycastle.jsl.openpgp.OpenPGPTestKeys;
import org.bouncycastle.jsl.openpgp.PGPObjectFactory;
import org.bouncycastle.jsl.openpgp.PGPPublicKey;
import org.bouncycastle.jsl.openpgp.PGPPublicKeyRing;
import org.bouncycastle.jsl.openpgp.PGPSecretKeyRing;
import org.bouncycastle.jsl.openpgp.PGPSignature;
import org.bouncycastle.jsl.openpgp.PGPSignatureList;
import org.bouncycastle.jsl.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.test.SimpleTest;

public class PGPSecretKeyRingTest
    extends SimpleTest
{
    @org.junit.Test
    public void test()
        throws Exception
    {
        org.bouncycastle.jsl.util.test.TestResult result = perform();
        if (!result.isSuccessful())
        {
            throw new junit.framework.AssertionFailedError(result.toString());
        }
    }

    public String getName()
    {
        return "PGPSecretKeyRingTest";
    }

    public void performTest()
        throws Exception
    {
        insertOrReplacePublicKeyTestWithRevocationInjection();
        replacePublicKeyRetainsExtraPublicKeysTest();
    }

    private void insertOrReplacePublicKeyTestWithRevocationInjection()
        throws IOException
    {
        PGPObjectFactory objFac = new JcaPGPObjectFactory(new BCPGInputStream(new ArmoredInputStream(
            new ByteArrayInputStream(Strings.toByteArray(OpenPGPTestKeys.ALICE_KEY)))));
        PGPSecretKeyRing sKeyRing = (PGPSecretKeyRing)objFac.nextObject();

        isEquals("Test key MUST consist of two component keys", 2, sKeyRing.size());
        isTrue("Initially there MUST NOT be a revocation signature present",
            !sKeyRing.getPublicKey().getSignaturesOfType(PGPSignature.KEY_REVOCATION).hasNext());

        objFac = new JcaPGPObjectFactory(new BCPGInputStream(new ArmoredInputStream(
            new ByteArrayInputStream(Strings.toByteArray(OpenPGPTestKeys.ALICE_REVOCATION_CERT)))));
        PGPSignatureList sigList = (PGPSignatureList)objFac.nextObject();
        PGPSignature revocation = sigList.get(0);

        // Inject revocation to primary key
        PGPPublicKey primaryKey = PGPPublicKey.addCertification(sKeyRing.getPublicKey(), revocation);

        // Replace primary key - the subkey must survive
        sKeyRing = PGPSecretKeyRing.insertOrReplacePublicKey(sKeyRing, primaryKey);
        isEquals("All keys are retained in the new key ring", 2, sKeyRing.size());

        isTrue("Revocation has been injected properly",
            sKeyRing.getPublicKey().getSignaturesOfType(PGPSignature.KEY_REVOCATION).hasNext());
    }

    private void replacePublicKeyRetainsExtraPublicKeysTest()
        throws IOException
    {
        PGPSecretKeyRing sKeyRing = (PGPSecretKeyRing)read(OpenPGPTestKeys.ALICE_KEY);
        PGPPublicKey extraKey = readSubkey(OpenPGPTestKeys.BOB_CERT);

        // No secret key for Bob's subkey, so it is inserted as an extra public key
        sKeyRing = PGPSecretKeyRing.insertOrReplacePublicKey(sKeyRing, extraKey);
        isEquals("Extra public key MUST be inserted", 1, countExtraPublicKeys(sKeyRing));

        PGPSignature aliceRevocation = ((PGPSignatureList)read(OpenPGPTestKeys.ALICE_REVOCATION_CERT)).get(0);
        PGPPublicKey primaryKey = PGPPublicKey.addCertification(sKeyRing.getPublicKey(), aliceRevocation);

        // Replacing a key with a secret key MUST NOT drop the extra public key
        sKeyRing = PGPSecretKeyRing.insertOrReplacePublicKey(sKeyRing, primaryKey);
        isEquals("insertOrReplacePublicKey() MUST retain all secret keys", 2, sKeyRing.size());
        isEquals("insertOrReplacePublicKey() MUST retain extra public keys", 1, countExtraPublicKeys(sKeyRing));
        isTrue("Extra public key MUST be unchanged", extraKey == sKeyRing.getExtraPublicKeys().next());

        // replacePublicKeys() MUST take the extra public key off the public ring as well
        PGPPublicKey updatedExtraKey = readSubkey(OpenPGPTestKeys.BOB_CERT);
        List<PGPPublicKey> publicKeys = new ArrayList<PGPPublicKey>();
        for (Iterator<PGPPublicKey> it = sKeyRing.getPublicKeys(); it.hasNext(); )
        {
            PGPPublicKey pk = (PGPPublicKey)it.next();
            publicKeys.add(pk.getKeyID() == extraKey.getKeyID() ? updatedExtraKey : pk);
        }

        sKeyRing = PGPSecretKeyRing.replacePublicKeys(sKeyRing, new PGPPublicKeyRing(publicKeys));
        isEquals("replacePublicKeys() MUST retain all secret keys", 2, sKeyRing.size());
        isEquals("replacePublicKeys() MUST retain extra public keys", 1, countExtraPublicKeys(sKeyRing));
        isTrue("replacePublicKeys() MUST replace the extra public key",
            updatedExtraKey == sKeyRing.getExtraPublicKeys().next());
    }

    private static PGPPublicKey readSubkey(String armoredCert)
        throws IOException
    {
        Iterator<PGPPublicKey> keys = ((PGPPublicKeyRing)read(armoredCert)).getPublicKeys();
        keys.next();
        return (PGPPublicKey)keys.next();
    }

    private static Object read(String armored)
        throws IOException
    {
        PGPObjectFactory objFac = new JcaPGPObjectFactory(new BCPGInputStream(new ArmoredInputStream(
            new ByteArrayInputStream(Strings.toByteArray(armored)))));
        return objFac.nextObject();
    }

    private static int countExtraPublicKeys(PGPSecretKeyRing sKeyRing)
    {
        int count = 0;
        for (Iterator<PGPPublicKey> it = sKeyRing.getExtraPublicKeys(); it.hasNext(); it.next())
        {
            count++;
        }
        return count;
    }

    public static void main(String[] args)
    {
        runTest(new PGPSecretKeyRingTest());
    }
}
