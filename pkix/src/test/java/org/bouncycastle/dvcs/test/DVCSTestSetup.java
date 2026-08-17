
package org.bouncycastle.dvcs.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.bouncycastle.jsl.test.JslTestProvider;
class DVCSTestSetup
    extends TestSetup
{
    public DVCSTestSetup(Test test)
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
