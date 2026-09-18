package org.bouncycastle.jsl.jsse.provider;

import java.security.GeneralSecurityException;

interface EngineCreator
{
    Object createInstance(Object constructorParameter)
        throws GeneralSecurityException;
}
