package org.bouncycastle.jsl.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jsl.openpgp.OpenPGPTestKeys;
import org.bouncycastle.jsl.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.jsl.openpgp.api.OpenPGPApi;
import org.bouncycastle.jsl.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.jsl.openpgp.api.OpenPGPDetachedSignatureProcessor;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.api.OpenPGPSignature;
import org.bouncycastle.jsl.openpgp.api.SignatureParameters;
import org.bouncycastle.jsl.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.test.SimpleTest;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Regression test: a document signature that has passed its own Signature Expiration Time (RFC 9580,
 * section 5.2.3.18, hashed subpacket type 3) must not be reported valid at that time.
 * <p>
 * {@code OpenPGPDocumentSignature.isValidAt(Date, OpenPGPPolicy)} checked that the signature was
 * cryptographically correct and that the issuing key was bound and signing-capable at the evaluation
 * time, but never consulted the signature's own expiration - so the method disagreed with
 * {@code isEffectiveAt(Date)} on the same object, and with its own javadoc, which names being
 * effective as one of the three validity criteria. Signature expiration (type 3) is a separate axis
 * from the issuing key's Key Expiration Time (type 9) that the {@code isBoundAt} calls cover.
 * <p>
 * {@code isValid()} and {@code isValid(policy)} evaluate at the signature's creation time, where a
 * signature is always inside its own window, so they are unaffected either way.
 */
public class OpenPGPDocumentSignatureExpiryTest
    extends SimpleTest
{
    @org.junit.Test
    public void test()
        throws Exception
    {
        org.bouncycastle.jsl.util.test.TestResult result = perform();
        if (!result.isSuccessful())
        {
            throw new junit.framework.AssertionFailedError(result.toString());
        }
    }

    private static final long LIFETIME_SECS = 3600L;
    private static final byte[] PLAINTEXT = Strings.toUTF8ByteArray("Hello, World!\n");

    public String getName()
    {
        return "OpenPGPDocumentSignatureExpiryTest";
    }

    public void performTest()
        throws Exception
    {
        // a FIPS module may serve none of these, or only some
        if (!JslTestProvider.supports("Signature.Ed25519", "KeyAgreement.X25519"))
        {
            return;
        }

        expiredSignatureIsNotValid();
        unexpiredSignatureIsValid();
        signatureWithoutExpiryStaysValid();
        isValidIsUnaffected();
    }

    private void expiredSignatureIsNotValid()
        throws Exception
    {
        OpenPGPSignature.OpenPGPDocumentSignature sig = verifiedSignature(LIFETIME_SECS);
        Date afterExpiry = offset(sig, LIFETIME_SECS + 60);

        isTrue("test setup: signature should carry an expiration time",
            sig.getExpirationTime() != null);
        isTrue("an expired signature should not be effective",
            !sig.isEffectiveAt(afterExpiry));
        isTrue("an expired signature must not be reported valid",
            !sig.isValidAt(afterExpiry));
    }

    private void unexpiredSignatureIsValid()
        throws Exception
    {
        // the compatibility assertion - inside its own lifetime the same signature is still valid
        OpenPGPSignature.OpenPGPDocumentSignature sig = verifiedSignature(LIFETIME_SECS);
        Date beforeExpiry = offset(sig, 60);

        isTrue("a signature inside its lifetime should be effective",
            sig.isEffectiveAt(beforeExpiry));
        isTrue("a signature inside its lifetime should be valid",
            sig.isValidAt(beforeExpiry));
    }

    private void signatureWithoutExpiryStaysValid()
        throws Exception
    {
        // a signature with no Signature Expiration Time never expires, whatever the evaluation time
        OpenPGPSignature.OpenPGPDocumentSignature sig = verifiedSignature(0);

        isTrue("test setup: signature should carry no expiration time",
            sig.getExpirationTime() == null);
        isTrue("a non-expiring signature should stay valid",
            sig.isValidAt(offset(sig, 10L * 365 * 86400)));
    }

    private void isValidIsUnaffected()
        throws Exception
    {
        // isValid() evaluates at the creation time, where a signature is inside its own window
        isTrue("isValid() should not be affected by the signature's expiration",
            verifiedSignature(LIFETIME_SECS).isValid());
    }

    /**
     * Create a detached signature which expires <pre>lifetimeSecs</pre> after its creation time - zero
     * meaning it never expires - and return it as verified through the high-level processor.
     */
    private OpenPGPSignature.OpenPGPDocumentSignature verifiedSignature(final long lifetimeSecs)
        throws Exception
    {
        OpenPGPApi api = new JcaOpenPGPApi(JslTestProvider.install());
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);

        List<OpenPGPSignature.OpenPGPDocumentSignature> created = api.createDetachedSignature()
            .addSigningKey(key, new SignatureParameters.Callback()
            {
                public SignatureParameters apply(SignatureParameters parameters)
                {
                    if (lifetimeSecs == 0)
                    {
                        return parameters;
                    }

                    return parameters.setHashedSubpacketsFunction(new SignatureSubpacketsFunction()
                    {
                        public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                        {
                            subpackets.setSignatureExpirationTime(true, lifetimeSecs);
                            return subpackets;
                        }
                    });
                }
            })
            .sign(new ByteArrayInputStream(PLAINTEXT));

        OpenPGPDetachedSignatureProcessor processor = api.verifyDetachedSignature();
        processor.addSignature(created.get(0).getSignature());
        processor.addVerificationCertificate(cert);

        List<OpenPGPSignature.OpenPGPDocumentSignature> verified =
            processor.process(new ByteArrayInputStream(PLAINTEXT));

        isEquals("test setup: one signature should be verified", 1, verified.size());

        return verified.get(0);
    }

    private Date offset(OpenPGPSignature.OpenPGPDocumentSignature sig, long secs)
    {
        return new Date(sig.getCreationTime().getTime() + 1000L * secs);
    }

    public static void main(String[] args)
    {
        JslTestProvider.install();

        runTest(new OpenPGPDocumentSignatureExpiryTest());
    }
}
