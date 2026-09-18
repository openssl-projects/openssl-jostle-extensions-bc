package org.bouncycastle.jsl.mail.smime.validator;

import org.bouncycastle.jsl.pkix.util.ErrorBundle;
import org.bouncycastle.jsl.pkix.util.LocalizedException;

public class SignedMailValidatorException extends LocalizedException
{

    public SignedMailValidatorException(ErrorBundle errorMessage, Throwable throwable)
    {
        super(errorMessage, throwable);
    }

    public SignedMailValidatorException(ErrorBundle errorMessage)
    {
        super(errorMessage);
    }
    
}
