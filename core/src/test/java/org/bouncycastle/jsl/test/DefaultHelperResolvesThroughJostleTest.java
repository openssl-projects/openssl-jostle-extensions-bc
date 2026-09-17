package org.bouncycastle.jsl.test;

import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.DefaultProviderName;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * A caller who names no provider still resolves through this library's provider. The JDK serves
 * HMAC-SHA256 too and sits ahead of JSL in the installed order, so a helper that named nobody
 * would answer with the JDK's implementation and nothing would look wrong.
 */
public class DefaultHelperResolvesThroughJostleTest
{
    private static final String SHARED_ALGORITHM = "HmacSHA256";

    private String original;

    @Before
    public void installProvider()
    {
        JslTestProvider.install();
        original = DefaultProviderName.getProviderName();
        DefaultProviderName.setProviderName(JslTestProvider.name());
    }

    @After
    public void restore()
    {
        DefaultProviderName.setProviderName(original);
    }

    @Test
    public void theDefaultHelperResolvesThroughTheNamedProvider()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("Mac." + SHARED_ALGORITHM);

        String viaJdk = Mac.getInstance(SHARED_ALGORITHM).getProvider().getName();
        assertTrue("this cell proves nothing unless another provider answers first",
            !JslTestProvider.name().equals(viaJdk));

        Mac mac = new DefaultJcaJceHelper().createMac(SHARED_ALGORITHM);

        assertEquals("a caller who names no provider must still get " + JslTestProvider.name(),
            JslTestProvider.name(), mac.getProvider().getName());
    }

    @Test
    public void anUnregisteredNameIsRefusedByName()
        throws Exception
    {
        DefaultProviderName.setProviderName("NoProviderAnswersToThis");

        try
        {
            new DefaultJcaJceHelper().createMac(SHARED_ALGORITHM);
            fail("an unregistered provider name was not refused");
        }
        catch (GeneralSecurityException e)
        {
            // Caught by the general type on purpose: the cell then compiles against a helper that
            // names no provider too, so reverting the helper shows up as a red rather than as a
            // compile error.
            assertEquals("the refusal must be the typed one", NoSuchProviderException.class, e.getClass());
            assertTrue("the refusal must name the provider that was asked for: " + e.getMessage(),
                e.getMessage().contains("NoProviderAnswersToThis"));
        }
    }

    /**
     * The documented escape hatch: a null name restores the JDK's own resolution, which is what a
     * caller who wants the platform's provider order sets.
     */
    @Test
    public void aNullNameRestoresTheJdkResolution()
        throws Exception
    {
        DefaultProviderName.setProviderName(null);

        Mac mac = new DefaultJcaJceHelper().createMac(SHARED_ALGORITHM);

        assertNotNull(mac);
        assertEquals("a null name must resolve exactly as the bare JCA call does",
            Mac.getInstance(SHARED_ALGORITHM).getProvider().getName(), mac.getProvider().getName());
    }
}
