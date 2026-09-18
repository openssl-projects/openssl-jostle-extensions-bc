package org.bouncycastle.jsl.cms;

import org.bouncycastle.jsl.asn1.cms.RecipientInfo;
import org.bouncycastle.jsl.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
