package org.bouncycastle.jsl.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;

import org.bouncycastle.jsl.asn1.cmp.Challenge;
import org.bouncycastle.jsl.asn1.cmp.PKIHeader;
import org.bouncycastle.jsl.asn1.cms.ContentInfo;
import org.bouncycastle.jsl.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jsl.cms.CMSEnvelopedData;
import org.bouncycastle.jsl.cms.CMSException;
import org.bouncycastle.jsl.cms.Recipient;
import org.bouncycastle.jsl.cms.RecipientInformation;
import org.bouncycastle.jsl.operator.DigestCalculator;
import org.bouncycastle.jsl.util.Arrays;

public class ChallengeContent
{
    private final Challenge challenge;
    private final DigestCalculator owfCalc;
    
    ChallengeContent(Challenge challenge, DigestCalculator owfCalc)
    {
        this.challenge = challenge;
        this.owfCalc = owfCalc;
    }

    public byte[] extractChallenge(PKIHeader sourceMessageHdr, Recipient recipient)
        throws CMPException
    {
        try
        {
            CMSEnvelopedData cmsEnvelopedData = new CMSEnvelopedData(new ContentInfo(PKCSObjectIdentifiers.envelopedData, challenge.getEncryptedRand()));

            Collection c = cmsEnvelopedData.getRecipientInfos().getRecipients();

            RecipientInformation recInfo = (RecipientInformation)c.iterator().next();

            byte[] recData = recInfo.getContent(recipient);

            Challenge.Rand rand = Challenge.Rand.getInstance(recData);

            if (!Arrays.constantTimeAreEqual(rand.getSender().getEncoded(), sourceMessageHdr.getSender().getEncoded()))
            {
                throw new CMPChallengeFailedException("incorrect sender found");
            }

            OutputStream digOut = owfCalc.getOutputStream();

            digOut.write(rand.getInt().getEncoded());

            digOut.close();

            if (!Arrays.constantTimeAreEqual(challenge.getWitness(), owfCalc.getDigest()))
            {
                throw new CMPChallengeFailedException("corrupted challenge found");
            }

            return rand.getInt().getValue().toByteArray();
        }
        catch (CMSException e)
        {
            throw new CMPException(e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new CMPException(e.getMessage(), e);
        }
    }
}
