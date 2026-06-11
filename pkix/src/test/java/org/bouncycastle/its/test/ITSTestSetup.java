package org.bouncycastle.its.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

class ITSTestSetup
    extends TestSetup
{
    public ITSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new JostleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
    }

}
