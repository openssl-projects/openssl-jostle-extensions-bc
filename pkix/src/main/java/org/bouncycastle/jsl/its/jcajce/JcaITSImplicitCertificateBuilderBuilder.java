package org.bouncycastle.jsl.its.jcajce;

import java.security.Provider;

import org.bouncycastle.jsl.its.ITSCertificate;
import org.bouncycastle.jsl.its.ITSImplicitCertificateBuilder;
import org.bouncycastle.jsl.oer.its.ieee1609dot2.ToBeSignedCertificate;
import org.bouncycastle.jsl.operator.OperatorCreationException;
import org.bouncycastle.jsl.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaITSImplicitCertificateBuilderBuilder
{
    private final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

    public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider)
    {
        this.digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName)
    {
        this.digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public ITSImplicitCertificateBuilder build(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
        throws OperatorCreationException
    {
        return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(), tbsCertificate);
    }
}
