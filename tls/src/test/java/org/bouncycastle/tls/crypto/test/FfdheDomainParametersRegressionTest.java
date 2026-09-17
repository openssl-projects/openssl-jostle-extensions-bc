package org.bouncycastle.tls.crypto.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.crypto.DHGroup;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.junit.Before;
import org.junit.Test;
import org.openssl.jostle.jcajce.spec.DHDomainParameterSpec;
import org.openssl.jostle.jcajce.spec.DHExtendedPublicKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The FFDHE subgroup order has to survive into the provider's DH parameters.
 * <p>
 * JSL reads Q only from its own {@code DHDomainParameterSpec} and refuses any other
 * {@code DHParameterSpec} subclass typed. The wrapper this exercises answers null on any exception,
 * so a refusal reaches the caller as a group leaving the supported set with nothing reported. This
 * pins the value rather than the call.
 */
public class FfdheDomainParametersRegressionTest
{
    private static final int[] FFDHE_GROUPS = new int[]{
        NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096,
        NamedGroup.ffdhe6144, NamedGroup.ffdhe8192};

    private JcaTlsCrypto crypto;

    @Before
    public void setUp()
    {
        JslTestProvider.install();
        JslTestProvider.assumeAlgorithm("AlgorithmParameters.DiffieHellman");

        crypto = new JcaTlsCryptoProvider().setProvider(JslTestProvider.provider()).create(new SecureRandom());
    }

    /**
     * The handshake coverage in {@code JcaTlsProtocolFfdheTest} takes an early return when the
     * crypto reports the group unsupported, so it can pass while testing nothing. This is the same
     * predicate, asserted rather than branched on.
     */
    @Test
    public void everyFfdheGroupIsReportedSupported()
    {
        for (int namedGroup : FFDHE_GROUPS)
        {
            assertTrue(NamedGroup.getText(namedGroup) + " is not reported supported, so the "
                + "handshake coverage for it would silently skip", crypto.hasNamedGroup(namedGroup));
        }
    }

    @Test
    public void everyFfdheGroupKeepsItsSubgroupOrder()
        throws Exception
    {
        for (int namedGroup : FFDHE_GROUPS)
        {
            String name = NamedGroup.getText(namedGroup);
            DHGroup expected = TlsDHUtils.getNamedDHGroup(namedGroup);
            assertNotNull(name + ": no standard group", expected);

            AlgorithmParameters params = crypto.getNamedGroupAlgorithmParameters(namedGroup);
            assertNotNull(name + ": the group is not supported at all", params);

            DHDomainParameterSpec spec = params.getParameterSpec(DHDomainParameterSpec.class);
            assertEquals(name + ": P did not survive", expected.getP(), spec.getP());
            assertEquals(name + ": G did not survive", expected.getG(), spec.getG());

            BigInteger q = spec.getQ();
            assertNotNull(name + ": Q was dropped on the way to the provider", q);
            assertEquals(name + ": Q did not survive", expected.getQ(), q);
        }
    }

    /**
     * A plain {@code DHParameterSpec} request still answers, and still carries the domain JSL was
     * initialised with - the downgrade must not be how Q goes missing.
     */
    @Test
    public void aPlainDhParameterSpecRequestStillCarriesTheDomain()
        throws Exception
    {
        DHGroup expected = TlsDHUtils.getNamedDHGroup(NamedGroup.ffdhe2048);

        AlgorithmParameters params = crypto.getNamedGroupAlgorithmParameters(NamedGroup.ffdhe2048);
        assertNotNull("ffdhe2048 is not supported at all", params);

        DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
        assertEquals("P did not survive", expected.getP(), spec.getP());
        assertEquals("G did not survive", expected.getG(), spec.getG());
    }

    /**
     * A peer value the provider rejects is refused when the key is imported, not later at
     * {@code doPhase}. The check refuses the degenerate values; nothing here states whether
     * subgroup membership is verified.
     */
    @Test
    public void aDegeneratePeerValueIsRefusedAtImport()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyFactory.DiffieHellman");

        DHGroup group = TlsDHUtils.getNamedDHGroup(NamedGroup.ffdhe2048);
        DHDomainParameterSpec domain = new DHDomainParameterSpec(
            group.getP(), group.getQ(), group.getG(), group.getL());
        KeyFactory kf = KeyFactory.getInstance("DiffieHellman", JslTestProvider.name());

        refuseAtImport(kf, BigInteger.ONE, domain, "y = 1");
        refuseAtImport(kf, group.getP().subtract(BigInteger.ONE), domain, "y = p-1");
    }

    private void refuseAtImport(KeyFactory kf, BigInteger y, DHDomainParameterSpec domain, String what)
    {
        try
        {
            kf.generatePublic(new DHExtendedPublicKeySpec(y, domain));
            fail(what + " was imported");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals(what + ": wrong refusal", "public value failed the DH public-key check",
                e.getMessage());
        }
    }

    /**
     * The two DH encoding forms do not mix. A peer key decoded from PKCS#3 {@code dhKeyAgreement}
     * is refused against an X9.42 {@code dhpublicnumber} private key, which is why both halves of
     * {@code DHUtil} have to build the same form.
     */
    @Test
    public void aPkcs3PeerIsRefusedAgainstX942Parameters()
        throws Exception
    {
        JslTestProvider.assumeAlgorithm("KeyAgreement.DiffieHellman");

        DHGroup group = TlsDHUtils.getNamedDHGroup(NamedGroup.ffdhe2048);
        DHDomainParameterSpec x942 = new DHDomainParameterSpec(
            group.getP(), group.getQ(), group.getG(), group.getL());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman", JslTestProvider.name());
        kpg.initialize(x942);
        KeyPair local = kpg.generateKeyPair();

        KeyPair x942Peer = kpg.generateKeyPair();

        kpg.initialize(new DHParameterSpec(group.getP(), group.getG(), group.getL()));
        BigInteger peerY = ((DHPublicKey)kpg.generateKeyPair().getPublic()).getY();

        KeyFactory kf = KeyFactory.getInstance("DiffieHellman", JslTestProvider.name());
        PublicKey pkcs3Peer = kf.generatePublic(
            new DHPublicKeySpec(peerY, group.getP(), group.getG()));

        KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman", JslTestProvider.name());
        ka.init(local.getPrivate());
        try
        {
            ka.doPhase(pkcs3Peer, true);
            fail("a PKCS#3 peer key was accepted against X9.42 parameters");
        }
        catch (InvalidKeyException e)
        {
            assertTrue("wrong refusal: " + e.getMessage(),
                e.getMessage().indexOf("decoded from a different DH encoding form") >= 0);
        }

        // and the same agreement succeeds once the peer carries the X9.42 form
        KeyAgreement agreed = KeyAgreement.getInstance("DiffieHellman", JslTestProvider.name());
        agreed.init(local.getPrivate());
        agreed.doPhase(kf.generatePublic(new DHExtendedPublicKeySpec(
            ((DHPublicKey)x942Peer.getPublic()).getY(), x942)), true);
        assertEquals("the agreed secret is not the field size", 256, agreed.generateSecret().length);
    }
}
