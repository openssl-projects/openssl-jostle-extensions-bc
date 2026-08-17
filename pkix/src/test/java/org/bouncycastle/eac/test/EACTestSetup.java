
package org.bouncycastle.eac.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.bouncycastle.jsl.test.JslTestProvider;
class EACTestSetup
    extends TestSetup
{
    public EACTestSetup(Test test)
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
