package org.bouncycastle.jcajce.util.test;

import org.bouncycastle.jcajce.util.DefaultProviderName;
import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * The name is global mutable state, so every test here restores whatever it found. The default
 * matters: nothing in this fork registers a provider called "BC", so a library site that still
 * named one would fail with NoSuchProviderException rather than fall back.
 */
public class DefaultProviderNameTest
{
    private final String original = DefaultProviderName.getProviderName();

    @After
    public void restore()
    {
        DefaultProviderName.setProviderName(original);
    }

    @Test
    public void testDefaultIsJsl()
    {
        assertEquals("JSL", original);
    }

    @Test
    public void testSetGetRoundTrips()
    {
        DefaultProviderName.setProviderName("JSLFIPS");
        assertEquals("JSLFIPS", DefaultProviderName.getProviderName());

        DefaultProviderName.setProviderName("SunJCE");
        assertEquals("SunJCE", DefaultProviderName.getProviderName());
    }

    @Test
    public void testNullMeansNoProviderNamed()
    {
        DefaultProviderName.setProviderName(null);
        assertNull(DefaultProviderName.getProviderName());
    }
}
