
package org.bouncycastle.mime.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import org.bouncycastle.jsl.test.JslTestProvider;
class MIMETestSetup
    extends TestSetup
{
    public MIMETestSetup(Test test)
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
