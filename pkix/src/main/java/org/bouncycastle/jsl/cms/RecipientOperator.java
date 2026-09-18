package org.bouncycastle.jsl.cms;

import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.jsl.operator.InputAEADDecryptor;
import org.bouncycastle.jsl.operator.InputDecryptor;
import org.bouncycastle.jsl.operator.MacCalculator;
import org.bouncycastle.jsl.util.io.TeeInputStream;

public class RecipientOperator
{
    private final Object operator;

    public RecipientOperator(InputDecryptor decryptor)
    {
        this.operator = decryptor;
    }

    public RecipientOperator(MacCalculator macCalculator)
    {
        this.operator = macCalculator;
    }

    public InputStream getInputStream(InputStream dataIn)
    {
        if (operator instanceof InputDecryptor)
        {
            return ((InputDecryptor)operator).getInputStream(dataIn);
        }
        else
        {
            return new TeeInputStream(dataIn, ((MacCalculator)operator).getOutputStream());
        }
    }

    public boolean isAEADBased()
    {
        return operator instanceof InputAEADDecryptor;
    }

    public OutputStream getAADStream()
    {
        return ((InputAEADDecryptor)operator).getAADStream();
    }

    public boolean isMacBased()
    {
        return operator instanceof MacCalculator;
    }

    public byte[] getMac()
    {
        if (operator instanceof MacCalculator)
        {
            return ((MacCalculator)operator).getMac();
        }
        else if (operator instanceof InputAEADDecryptor)
        {
            return ((InputAEADDecryptor)operator).getMAC();
        }
        return null;
    }
}
