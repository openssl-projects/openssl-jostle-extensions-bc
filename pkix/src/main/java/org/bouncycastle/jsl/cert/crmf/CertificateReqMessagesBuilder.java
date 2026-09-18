package org.bouncycastle.jsl.cert.crmf;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jsl.asn1.crmf.CertReqMessages;
import org.bouncycastle.jsl.asn1.crmf.CertReqMsg;

public class CertificateReqMessagesBuilder
{
    private final List<CertReqMsg> requests = new ArrayList<CertReqMsg>();

    public CertificateReqMessagesBuilder()
    {
    }

    public void addRequest(CertificateRequestMessage request)
    {
        requests.add(request.toASN1Structure());
    }

    public CertificateReqMessages build()
    {
        CertificateReqMessages certificateReqMessages = new CertificateReqMessages(
            new CertReqMessages((CertReqMsg[])requests.toArray(new CertReqMsg[0])));

        requests.clear();

        return certificateReqMessages;
    }
}
