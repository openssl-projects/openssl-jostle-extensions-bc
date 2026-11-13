package org.bouncycastle.jsl.openpgp.api.test;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.jsl.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jsl.openpgp.PGPException;
import org.bouncycastle.jsl.openpgp.api.OpenPGPApi;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Base of the OpenPGP API tests. Upstream runs each test with its lightweight API and with the JCA API
 * over BouncyCastle. This library carries the JCA API only, and runs it over the provider under test.
 */
public abstract class APITest
        extends AbstractPacketTest
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

    @Override
    public void performTest()
            throws Exception
    {
        performTestWith(new JcaOpenPGPApi(JslTestProvider.install()));
    }

    public Date currentTimeRounded()
    {
        Date now = new Date();
        return new Date((now.getTime() / 1000) * 1000); // rounded to seconds
    }

    protected abstract void performTestWith(OpenPGPApi api)
        throws PGPException, IOException;
}
