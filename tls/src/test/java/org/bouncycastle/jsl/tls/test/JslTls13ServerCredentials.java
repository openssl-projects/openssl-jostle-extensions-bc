package org.bouncycastle.jsl.tls.test;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.jsl.test.JslTestProvider;
import org.bouncycastle.jsl.tls.SignatureAlgorithm;
import org.bouncycastle.jsl.tls.TlsContext;
import org.bouncycastle.jsl.tls.TlsCredentialedSigner;

/**
 * The TLS 1.3 signer credential the KEM and hybrid mock servers use, chosen against the provider
 * actually under test.
 * <p>
 * bc-java's mocks sign the TLS 1.3 CertificateVerify with an {@code rsa_pkcs1} credential - see the
 * {@code TODO[tls13]} in {@code MockTlsKemServer.getCredentials} - and {@code JcaTlsRSASigner}
 * performs that through {@code Signature "NoneWithRSA"}. JSLFIPS registers that name and then
 * refuses it at {@code initSign}, on every FIPS module, so the handshake dies with
 * {@code internal_error(80)} before the KEM group under test has been exercised at all. That
 * refusal is deliberate - raw RSA is not approved, so JSLFIPS registers the name against an SPI
 * that cannot resolve a {@code NONE} digest, and a test on the provider side pins it. See
 * **Raw RSA on JSLFIPS** in {@code .claude/guides/testing.md}.
 * <p>
 * So substitute an ECDSA credential where raw RSA signing cannot actually be performed, rather
 * than skipping the class. Probe rather than branch on the provider name: the answer is a property
 * of the provider under test, and if JSLFIPS ever serves this the substitution retires itself. The server credential is scaffolding, not the thing under test - the same reasoning that
 * has {@code CMSTestUtil} sign its test certificates with SHA-256 under JSLFIPS instead of giving
 * up on every test that needs a certificate. Both mock clients already trust
 * {@code x509-server-ecdsa.pem}, and neither sends a client certificate under TLS 1.3
 * ({@code getClientCredentials} returns null when the request carries no certificate types), so
 * the client side needs no equivalent.
 */
class JslTls13ServerCredentials
{
    private JslTls13ServerCredentials()
    {
    }

    static TlsCredentialedSigner load(TlsContext context)
        throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

        // probe, do not ask which provider or which module this is: what matters is whether a
        // raw RSA signature can actually be produced here. canSign() caches per JVM, so the
        // RSA-2048 keypair it generates costs one handshake's worth of work at most.
        //
        // ECDSA is the substitute because both mock clients already trust x509-server-ecdsa.pem
        // and JSLFIPS serves ECDSA on every module.
        short signatureAlgorithm = JslTestProvider.canSign("NoneWithRSA", "RSA", 2048)
            ? SignatureAlgorithm.rsa
            : SignatureAlgorithm.ecdsa;

        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, signatureAlgorithm);
    }
}
