package org.bouncycastle.cert.test;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class MLKEMCredentialsTest
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
        return "MLKEMCredentials";
    }

    public void performTest()
        throws Exception
    {
        checkSampleCredentials(SampleCredentials.ML_KEM_512(), SampleCredentials.ML_DSA_44());
        checkSampleCredentials(SampleCredentials.ML_KEM_768(), SampleCredentials.ML_DSA_65());
        checkSampleCredentials(SampleCredentials.ML_KEM_1024(), SampleCredentials.ML_DSA_87());
    }

    private static void checkSampleCredentials(SampleCredentials subject, SampleCredentials issuer)
        throws GeneralSecurityException
    {
        subject.getCertificate().verify(issuer.getCertificate().getPublicKey(), JostleProvider.PROVIDER_NAME);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new JostleProvider());

        runTest(new MLKEMCredentialsTest());
    }
}
