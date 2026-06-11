
package org.bouncycastle.dvcs.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

class DVCSTestSetup
    extends TestSetup
{
    public DVCSTestSetup(Test test)
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
