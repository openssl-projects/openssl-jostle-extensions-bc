package org.bouncycastle.cert.test;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.util.test.SimpleTest;

public class MLKEMCredentialsTest
    extends SimpleTest
{
    @org.junit.Test
    public void test()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyPairGenerator.ML-KEM-512");
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
        subject.getCertificate().verify(issuer.getCertificate().getPublicKey(), JslTestProvider.name());
    }

    public static void main(String[] args)
    {
        JslTestProvider.install();

        runTest(new MLKEMCredentialsTest());
    }
}
