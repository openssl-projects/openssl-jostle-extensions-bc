package org.bouncycastle.its.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.bouncycastle.jsl.test.JslTestProvider;
class ITSTestSetup
    extends TestSetup
{
    public ITSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        JslTestProvider.install();
    }

    protected void tearDown()
    {
        Security.removeProvider(JslTestProvider.name());
    }

}
