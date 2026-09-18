package org.bouncycastle.jsl.openpgp;

public class PGPExtendedKeyHeader
{
    private final String name;
    private final String value;

    public PGPExtendedKeyHeader(String name, String value)
    {
        this.name = name;
        this.value = value;
    }

    public String getName()
    {
        return name;
    }

    public String getValue()
    {
        return value;
    }
}
