package org.bouncycastle.cms.test;

import junit.extensions.TestSetup;
import junit.framework.Test;

import java.security.Security;

import org.bouncycastle.jsl.test.JslTestProvider;
class CMSTestSetup extends TestSetup
{
    public CMSTestSetup(Test test)
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
