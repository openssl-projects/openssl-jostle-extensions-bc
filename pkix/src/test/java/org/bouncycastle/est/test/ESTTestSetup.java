
package org.bouncycastle.est.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

class ESTTestSetup
    extends TestSetup
{
    public ESTTestSetup(Test test)
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
