package org.bouncycastle.cert.test;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class MLDSACredentialsTest
    extends SimpleTest
{
    @org.junit.Test
    public void test()
        throws Exception
    {
        org.bouncycastle.util.test.TestResult result = perform();
        if (!result.isSuccessful())
        {
            throw new junit.framework.AssertionFailedError(result.toString());
        }
    }

    public String getName()
    {
        return "MLDSACredentials";
    }

    public void performTest()
        throws Exception
    {
        checkSampleCredentials(SampleCredentials.ML_DSA_44());
        checkSampleCredentials(SampleCredentials.ML_DSA_65());
        checkSampleCredentials(SampleCredentials.ML_DSA_87());
    }

    private static void checkSampleCredentials(SampleCredentials creds)
        throws GeneralSecurityException
    {
        X509Certificate cert = creds.getCertificate();
        PublicKey pubKey = cert.getPublicKey();
        cert.verify(pubKey, JostleProvider.PROVIDER_NAME);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new JostleProvider());

        runTest(new MLDSACredentialsTest());
    }
}
