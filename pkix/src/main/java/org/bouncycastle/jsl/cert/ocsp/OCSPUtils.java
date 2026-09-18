package org.bouncycastle.jsl.cert.ocsp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jsl.asn1.ASN1GeneralizedTime;
import org.bouncycastle.jsl.asn1.x509.Extensions;
import org.bouncycastle.jsl.cert.X509CertificateHolder;
import org.bouncycastle.jsl.util.Exceptions;
class OCSPUtils
{
    static final X509CertificateHolder[] EMPTY_CERTS = new X509CertificateHolder[0];

    static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
    static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

    static Date extractDate(ASN1GeneralizedTime time)
    {
        try
        {
            return time.getDate();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalStateException("exception processing GeneralizedTime", e);
        }
    }

    static Set getCriticalExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
    }

    static Set getNonCriticalExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_SET;
        }

        // TODO: should probably produce a set that imposes correct ordering
        return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
    }

    static List getExtensionOIDs(Extensions extensions)
    {
        if (extensions == null)
        {
            return EMPTY_LIST;
        }

        return Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
    }
}
