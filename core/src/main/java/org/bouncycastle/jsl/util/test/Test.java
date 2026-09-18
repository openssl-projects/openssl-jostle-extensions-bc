package org.bouncycastle.jsl.util.test;

public interface Test
{
    String getName();

    TestResult perform();
}
