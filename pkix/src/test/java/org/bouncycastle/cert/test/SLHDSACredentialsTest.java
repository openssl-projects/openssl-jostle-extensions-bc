package org.bouncycastle.cert.test;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.util.test.SimpleTest;

public class SLHDSACredentialsTest
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
        return "SLHDSACredentials";
    }

    public void performTest()
        throws Exception
    {
        checkSampleCredentials(SampleCredentials.SLH_DSA_SHA2_128S());
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

        runTest(new SLHDSACredentialsTest());
    }
}
