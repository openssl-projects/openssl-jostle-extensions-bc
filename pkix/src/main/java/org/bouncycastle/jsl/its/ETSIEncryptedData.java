package org.bouncycastle.jsl.its;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jsl.asn1.ASN1Encodable;
import org.bouncycastle.jsl.oer.Element;
import org.bouncycastle.jsl.oer.OEREncoder;
import org.bouncycastle.jsl.oer.OERInputStream;
import org.bouncycastle.jsl.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.jsl.oer.its.ieee1609dot2.EncryptedData;
import org.bouncycastle.jsl.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.jsl.oer.its.ieee1609dot2.RecipientInfo;
import org.bouncycastle.jsl.oer.its.template.etsi103097.EtsiTs103097Module;
import org.bouncycastle.jsl.util.CollectionStore;
import org.bouncycastle.jsl.util.Store;

public class ETSIEncryptedData
{
    private static final Element oerDef = EtsiTs103097Module.EtsiTs103097Data_Encrypted.build();

    private final EncryptedData encryptedData;

    public ETSIEncryptedData(byte[] oerEncoded)
        throws IOException
    {
        this(new ByteArrayInputStream(oerEncoded));
    }

    public ETSIEncryptedData(InputStream str)
        throws IOException
    {
        OERInputStream oerIn;
        if (str instanceof OERInputStream)
        {
            oerIn = (OERInputStream)str;
        }
        else
        {
            oerIn = new OERInputStream(str);
        }
        ASN1Encodable asn1 = oerIn.parse(oerDef);

        Ieee1609Dot2Content content = EtsiTs103097DataEncrypted.getInstance(asn1).getContent();
        if (content.getChoice() != Ieee1609Dot2Content.encryptedData)
        {
            throw new IllegalStateException("EtsiTs103097Data-Encrypted did not have encrypted data content");
        }
        this.encryptedData = EncryptedData.getInstance(content.getIeee1609Dot2Content());
    }

    ETSIEncryptedData(EncryptedData data)
    {
        this.encryptedData = data;
    }

    public byte[] getEncoded()
    {
        return OEREncoder.toByteArray(new EtsiTs103097DataEncrypted(
            Ieee1609Dot2Content
                .encryptedData(encryptedData)
        ), oerDef);
    }

    public EncryptedData getEncryptedData()
    {
        return encryptedData;
    }

    public Store<ETSIRecipientInfo> getRecipients()
    {
        List<ETSIRecipientInfo> recipients = new ArrayList<ETSIRecipientInfo>();
        for (RecipientInfo ri : encryptedData.getRecipients().getRecipientInfos())
        {
            recipients.add(new ETSIRecipientInfo(encryptedData, ri));
        }
        return new CollectionStore<ETSIRecipientInfo>(recipients);
    }

}
