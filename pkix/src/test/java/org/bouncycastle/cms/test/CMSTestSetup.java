package org.bouncycastle.cms.test;

import junit.extensions.TestSetup;
import junit.framework.Test;

import java.security.Security;

import org.openssl.jostle.jcajce.provider.JostleProvider;

class CMSTestSetup extends TestSetup
{
    public CMSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new JostleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("JSL");
    }
}
