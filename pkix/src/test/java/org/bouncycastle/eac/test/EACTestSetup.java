
package org.bouncycastle.eac.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

class EACTestSetup
    extends TestSetup
{
    public EACTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new org.openssl.jostle.jcajce.provider.JostleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
    }

}
