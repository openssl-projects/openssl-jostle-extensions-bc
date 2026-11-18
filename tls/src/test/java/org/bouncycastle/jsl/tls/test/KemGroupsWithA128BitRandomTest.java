package org.bouncycastle.jsl.tls.test;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.tls.AbstractTlsClient;
import org.bouncycastle.jsl.tls.AbstractTlsServer;
import org.bouncycastle.jsl.tls.AlertDescription;
import org.bouncycastle.jsl.tls.BasicTlsPSKExternal;
import org.bouncycastle.jsl.tls.CipherSuite;
import org.bouncycastle.jsl.tls.NamedGroup;
import org.bouncycastle.jsl.tls.PRFAlgorithm;
import org.bouncycastle.jsl.tls.ProtocolVersion;
import org.bouncycastle.jsl.tls.PskIdentity;
import org.bouncycastle.jsl.tls.TlsAuthentication;
import org.bouncycastle.jsl.tls.TlsClientProtocol;
import org.bouncycastle.jsl.tls.TlsCredentials;
import org.bouncycastle.jsl.tls.TlsFatalAlert;
import org.bouncycastle.jsl.tls.TlsPSK;
import org.bouncycastle.jsl.tls.TlsPSKExternal;
import org.bouncycastle.jsl.tls.TlsServerProtocol;
import org.bouncycastle.jsl.tls.TlsUtils;
import org.bouncycastle.jsl.tls.crypto.TlsCrypto;
import org.bouncycastle.jsl.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.jsl.util.Strings;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * The ML-KEM and hybrid groups with an application random that reports 128-bit strength, which is what
 * {@code new SecureRandom()} gives on Windows from Java 9 (the JDK's default DRBG). The provider refuses such a
 * random for ML-KEM-768 and ML-KEM-1024, so the TLS code must not pass the application's random to it.
 */
public class KemGroupsWithA128BitRandomTest
{

    @Rule
    public TestName testName = new TestName();
    private static final int[] GROUPS = { NamedGroup.MLKEM768, NamedGroup.MLKEM1024, NamedGroup.X25519MLKEM768,
        NamedGroup.SecP256r1MLKEM768, NamedGroup.SecP384r1MLKEM1024 };

    private static final byte[] IDENTITY = Strings.toUTF8ByteArray("client");
    private static final byte[] PSK = Strings.toUTF8ByteArray("a pre-shared key for the KEM groups");

    @Test
    public void everyGroupTheProviderServesIsOfferedWithA128BitRandom()
        throws Exception
    {
        TlsCrypto crypto = crypto(jdkDrbg128());
        TlsCrypto reference = crypto(null);

        int checked = 0;
        for (int i = 0; i != GROUPS.length; i++)
        {
            if (!servedByProvider(reference, GROUPS[i]))
            {
                continue;
            }
            assertTrue(NamedGroup.getText(GROUPS[i]) + " is not offered with a 128-bit random",
                TlsUtils.isSupportedNamedGroup(crypto, GROUPS[i]));
            ++checked;
        }
        assumeTrue("the provider serves none of the groups", checked > 0);
    }

    @Test
    public void everyGroupTheProviderServesCompletesAHandshakeWithA128BitRandom()
        throws Exception
    {
        SecureRandom random = jdkDrbg128();
        TlsCrypto reference = crypto(null);

        int checked = 0;
        for (int i = 0; i != GROUPS.length; i++)
        {
            int group = GROUPS[i];
            if (!servedByProvider(reference, group))
            {
                continue;
            }

            int[] negotiated = handshake(crypto(random), crypto(random), group);

            assertEquals(NamedGroup.getText(group) + ": the client's key share group", group, negotiated[0]);
            assertEquals(NamedGroup.getText(group) + ": the server's key share group", group, negotiated[1]);
            ++checked;
        }
        assumeTrue("the provider serves none of the groups", checked > 0);
    }

    /**
     * The JDK's own DRBG at its default configuration: the default random on Windows from Java 9, reporting 128-bit
     * strength. Asked of SUN by name, so that the provider under test, which registers a DRBG of its own, cannot
     * stand in for it. Java 8 has none, and its default random reports no strength, so the case does not arise.
     */
    private SecureRandom jdkDrbg128()
    {
        SecureRandom random;
        try
        {
            random = SecureRandom.getInstance("DRBG", "SUN");
        }
        catch (GeneralSecurityException e)
        {
            skip("the JDK has no DRBG SecureRandom (Java 8), so its default reports no strength and the provider"
                + " checks none");
            return null;
        }
        String parameters = reportedParameters(random);
        if (parameters == null)
        {
            skip("the JDK cannot report a SecureRandom's strength (Java 8), so the provider checks none");
            return null;
        }
        assertEquals("the JDK's DRBG provider", "SUN", random.getProvider().getName());
        assertEquals("the JDK's DRBG algorithm", "DRBG", random.getAlgorithm());
        assertTrue("the JDK's default DRBG reports 128-bit strength: " + parameters, parameters.startsWith("128,"));
        return random;
    }

    private void skip(String reason)
    {
        System.out.println("[skipped] " + testName.getMethodName() + ": " + reason);
        assumeTrue(reason, false);
    }

    /** SecureRandom.getParameters() is Java 9 and later; these tests also compile for Java 8. Null when absent. */
    private static String reportedParameters(SecureRandom random)
    {
        Method getParameters;
        try
        {
            getParameters = SecureRandom.class.getMethod("getParameters");
        }
        catch (NoSuchMethodException e)
        {
            return null;
        }
        try
        {
            return String.valueOf(getParameters.invoke(random));
        }
        catch (Exception e)
        {
            throw new IllegalStateException("cannot read the SecureRandom parameters", e);
        }
    }

    private static TlsCrypto crypto(SecureRandom random)
    {
        return new JcaTlsCryptoProvider().setProvider(JslTestProvider.install()).create(random);
    }

    /** Whether the provider serves the group at all, judged with no application random. */
    private static boolean servedByProvider(TlsCrypto reference, int group)
    {
        if (TlsUtils.isSupportedNamedGroup(reference, group))
        {
            return true;
        }
        System.out.println("[skipped] " + NamedGroup.getText(group) + ": " + JslTestProvider.name()
            + " does not serve the group");
        return false;
    }

    /** TLS 1.3 with an external PSK and psk_dhe_ke, so the one offered group carries the key exchange. */
    private static int[] handshake(TlsCrypto clientCrypto, TlsCrypto serverCrypto, int group)
        throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        final TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);
        final Server server = new Server(serverCrypto, group);
        final Exception[] serverFailure = new Exception[1];
        Thread serverThread = new Thread()
        {
            public void run()
            {
                try
                {
                    serverProtocol.accept(server);
                }
                catch (Exception e)
                {
                    serverFailure[0] = e;
                }
            }
        };
        serverThread.start();

        Client client = new Client(clientCrypto, group);
        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        // Only the completed handshake is of interest; closing both ends would race on the pipes.
        try
        {
            clientProtocol.connect(client);
        }
        finally
        {
            // bounded, so that a server blocked on a failed client cannot hang the run
            serverThread.join(60000);
        }

        if (serverFailure[0] != null)
        {
            throw serverFailure[0];
        }
        return new int[]{ client.negotiatedGroup, server.negotiatedGroup };
    }

    private static TlsPSKExternal psk(TlsCrypto crypto)
    {
        return new BasicTlsPSKExternal(IDENTITY, crypto.createSecret(PSK), PRFAlgorithm.tls13_hkdf_sha256);
    }

    private static class Client
        extends AbstractTlsClient
    {
        private final int group;
        int negotiatedGroup = -1;

        Client(TlsCrypto crypto, int group)
        {
            super(crypto);
            this.group = group;
        }

        protected Vector getSupportedGroups(Vector namedGroupRoles)
        {
            return TlsUtils.vectorOfOne(Integer.valueOf(group));
        }

        protected int[] getSupportedCipherSuites()
        {
            return new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public Vector getExternalPSKs()
        {
            return TlsUtils.vectorOfOne(psk(getCrypto()));
        }

        public void notifySelectedPSK(TlsPSK selectedPSK)
            throws IOException
        {
            if (null == selectedPSK)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public void notifyHandshakeComplete()
            throws IOException
        {
            super.notifyHandshakeComplete();
            negotiatedGroup = context.getSecurityParametersConnection().getNegotiatedGroup();
        }
    }

    private static class Server
        extends AbstractTlsServer
    {
        private final int group;
        int negotiatedGroup = -1;

        Server(TlsCrypto crypto, int group)
        {
            super(crypto);
            this.group = group;
        }

        public int[] getSupportedGroups()
        {
            return new int[]{ group };
        }

        protected int[] getSupportedCipherSuites()
        {
            return new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 };
        }

        protected ProtocolVersion[] getSupportedVersions()
        {
            return ProtocolVersion.TLSv13.only();
        }

        public TlsCredentials getCredentials()
        {
            return null;
        }

        public TlsPSKExternal getExternalPSK(Vector identities)
        {
            PskIdentity match = new PskIdentity(IDENTITY, 0L);
            for (int i = 0; i < identities.size(); ++i)
            {
                if (match.equals(identities.elementAt(i)))
                {
                    return psk(getCrypto());
                }
            }
            return null;
        }

        public void notifyHandshakeComplete()
            throws IOException
        {
            super.notifyHandshakeComplete();
            negotiatedGroup = context.getSecurityParametersConnection().getNegotiatedGroup();
        }
    }
}
