package org.bouncycastle.jsl.cert.cmp;

import java.math.BigInteger;

import org.bouncycastle.jsl.asn1.cmp.CMPCertificate;
import org.bouncycastle.jsl.asn1.cmp.CertStatus;
import org.bouncycastle.jsl.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.cert.X509CertificateHolder;
import org.bouncycastle.jsl.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.jsl.operator.DigestCalculator;
import org.bouncycastle.jsl.operator.DigestCalculatorProvider;
import org.bouncycastle.jsl.operator.OperatorCreationException;
import org.bouncycastle.jsl.util.Arrays;

public class CertificateStatus
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;    
    private CertStatus certStatus;

    CertificateStatus(DigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
    {
        this.digestAlgFinder = digestAlgFinder;
        this.certStatus = certStatus;
    }

    public PKIStatusInfo getStatusInfo()
    {
        return certStatus.getStatusInfo();
    }

    public BigInteger getCertRequestID()
    {
        return certStatus.getCertReqId().getValue();
    }

    public boolean isVerified(X509CertificateHolder certHolder, DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        return isVerified(new CMPCertificate(certHolder.toASN1Structure()), certHolder.getSignatureAlgorithm(),
            digesterProvider);
    }

    public boolean isVerified(CMPCertificate cmpCert, AlgorithmIdentifier signatureAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        byte[] certHash = CMPUtil.calculateCertHash(cmpCert, signatureAlgorithm, digesterProvider, digestAlgFinder);

        return Arrays.constantTimeAreEqual(certStatus.getCertHash().getOctets(), certHash);
    }
}
