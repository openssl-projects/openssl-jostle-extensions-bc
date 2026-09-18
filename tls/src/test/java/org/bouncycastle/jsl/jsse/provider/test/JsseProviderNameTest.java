package org.bouncycastle.jsl.jsse.provider.test;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jsl.jsse.provider.BouncyCastleJsseProvider;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;

/**
 * The JSSE provider registers as {@code JSLJSSE}, not {@code BCJSSE}.
 * <p>
 * Both jars can be installed in one JVM, and a JCA provider name is a primary key: two providers
 * claiming {@code BCJSSE} means whichever registered first wins and the other is unreachable by
 * name. This pins the name so it cannot drift back, and pins that nothing of ours answers to
 * BouncyCastle's.
 */
public class JsseProviderNameTest
{
    @Test
    public void theProviderRegistersUnderItsOwnNameAndNotBouncyCastles()
    {
        assertEquals("the declared provider name changed", "JSLJSSE",
            BouncyCastleJsseProvider.PROVIDER_NAME);

        Provider installed = new BouncyCastleJsseProvider();
        assertEquals("the instance does not carry the declared name", "JSLJSSE", installed.getName());

        boolean added = Security.getProvider("JSLJSSE") == null;
        if (added)
        {
            Security.addProvider(installed);
        }
        try
        {
            assertSame("JSLJSSE does not resolve to this provider", installed.getClass(),
                Security.getProvider("JSLJSSE").getClass());

            // Nothing of ours may answer to BouncyCastle's name. If a real bctls is ever on the
            // classpath this stays true: that provider is not one of ours.
            Provider bc = Security.getProvider("BCJSSE");
            assertFalse("this fork registered itself as BCJSSE",
                bc instanceof BouncyCastleJsseProvider);
        }
        finally
        {
            if (added)
            {
                Security.removeProvider("JSLJSSE");
            }
        }
    }
}
