package org.bouncycastle.jsl.test;

import org.bouncycastle.jsl.test.JslTestProvider;

import java.security.Provider;
import java.security.Security;

import org.junit.BeforeClass;

/**
 * Shared setup for the JSL compatibility-library tests: installs the OpenSSL
 * Jostle provider (name {@code JslTestProvider.name()}) once for the JVM. The provider delegates
 * crypto to OpenSSL via JNI/FFI, so these tests exercise the full path:
 * bc asn.1/operator/cert layer (core/util/pkix) -> JCA -> JSL -> OpenSSL.
 */
public abstract class JostleProviderTestBase
{
    public static final String JSL = JslTestProvider.name();


    @BeforeClass
    public static void installProvider()
        throws Exception
    {
        JslTestProvider.install();
    }
}
