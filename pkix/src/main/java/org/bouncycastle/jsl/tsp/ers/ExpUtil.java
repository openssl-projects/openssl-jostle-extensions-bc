package org.bouncycastle.jsl.tsp.ers;

class ExpUtil
{
    static IllegalStateException createIllegalState(String message, Throwable cause)
    {
        return new IllegalStateException(message, cause);
    }
}
