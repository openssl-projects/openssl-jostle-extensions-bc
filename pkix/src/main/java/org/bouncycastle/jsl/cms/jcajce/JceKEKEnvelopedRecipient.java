package org.bouncycastle.jsl.cms.jcajce;

import java.io.InputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.cms.CMSException;
import org.bouncycastle.jsl.cms.RecipientOperator;
import org.bouncycastle.jsl.jcajce.io.CipherInputStream;
import org.bouncycastle.jsl.operator.InputDecryptor;

public class JceKEKEnvelopedRecipient
    extends JceKEKRecipient
{
    public JceKEKEnvelopedRecipient(SecretKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                return new CipherInputStream(dataOut, dataCipher);
            }
        });
    }
}
