package org.bouncycastle.jsl.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jsl.bcpg.BCPGOutputStream;
import org.bouncycastle.jsl.openpgp.OpenPGPTestKeys;
import org.bouncycastle.jsl.openpgp.PGPLiteralData;
import org.bouncycastle.jsl.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.jsl.openpgp.api.OpenPGPApi;
import org.bouncycastle.jsl.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.jsl.openpgp.api.OpenPGPDefaultPolicy;
import org.bouncycastle.jsl.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.jsl.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.jsl.openpgp.api.OpenPGPSignature;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;
import org.bouncycastle.jsl.util.test.SimpleTest;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Regression test: the {@link OpenPGPPolicy} an {@link OpenPGPApi} was configured with must govern
 * inline message signature verification.
 * <p>
 * Both verify paths of {@link OpenPGPMessageInputStream} - the one-pass one and the prefixed-signature
 * one - read the policy to hand to {@code sanitize()} from the processor. They read it from the
 * implementation's own default rather than from the processor's configuration, so a policy supplied
 * through the documented {@code OpenPGPApi(implementation, policy)} constructor was ignored while
 * verifying a message: a signature the configured policy rejects came back from
 * {@code getResult().getSignatures()} with {@code isTestedCorrect()} true. The detached-signature
 * processor already used its configured policy, as did the decompressed-size bound on this same
 * processor, which is what made the omission a one-off.
 */
public class OpenPGPConfiguredPolicyTest
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

    private static final byte[] PLAINTEXT = Strings.toUTF8ByteArray("Hello, World!\n");

    public String getName()
    {
        return "OpenPGPConfiguredPolicyTest";
    }

    public void performTest()
        throws Exception
    {
        // a FIPS module may serve none of these, or only some
        if (!JslTestProvider.supports("Signature.Ed25519", "KeyAgreement.X25519"))
        {
            return;
        }

        configuredPolicyRejectsOnePassSignature();
        configuredPolicyRejectsPrefixedSignature();
        defaultPolicyStillAcceptsOnePassSignature();
        defaultPolicyStillAcceptsPrefixedSignature();
    }

    private void configuredPolicyRejectsOnePassSignature()
        throws Exception
    {
        isEquals("configured policy must be applied to a one-pass signature",
            0, verify(onePassSignedMessage(), strictApi()));
    }

    private void configuredPolicyRejectsPrefixedSignature()
        throws Exception
    {
        isEquals("configured policy must be applied to a prefixed signature",
            0, verify(prefixedSignedMessage(), strictApi()));
    }

    private void defaultPolicyStillAcceptsOnePassSignature()
        throws Exception
    {
        // the compatibility assertion - the message is fine, only the strict policy above rejects it
        isEquals("default policy should accept the one-pass signature",
            1, verify(onePassSignedMessage(), new JcaOpenPGPApi(JslTestProvider.install())));
    }

    private void defaultPolicyStillAcceptsPrefixedSignature()
        throws Exception
    {
        isEquals("default policy should accept the prefixed signature",
            1, verify(prefixedSignedMessage(), new JcaOpenPGPApi(JslTestProvider.install())));
    }

    /**
     * Return an api whose configured policy rejects every document signature hash algorithm, supplied
     * through the documented two-argument constructor.
     */
    private OpenPGPApi strictApi()
    {
        OpenPGPPolicy strict = new OpenPGPDefaultPolicy()
        {
            public boolean isAcceptableDocumentSignatureHashAlgorithm(int hashAlgorithmId, Date signatureCreationTime)
            {
                return false;
            }
        };

        return new JcaOpenPGPApi(JslTestProvider.install(), strict);
    }

    /**
     * Verify the given message and return the number of signatures reported as correct.
     */
    private int verify(byte[] message, OpenPGPApi api)
        throws Exception
    {
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);

        OpenPGPMessageInputStream in = api.decryptAndOrVerifyMessage()
            .addVerificationCertificate(cert)
            .process(new ByteArrayInputStream(message));
        Streams.drain(in);
        in.close();

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = in.getResult().getSignatures();
        for (int i = 0; i != signatures.size(); i++)
        {
            isTrue("a reported signature should have been tested correct",
                signatures.get(i).isTestedCorrect());
        }
        return signatures.size();
    }

    /**
     * A one-pass signed message, as the high-level generator produces it.
     */
    private byte[] onePassSignedMessage()
        throws Exception
    {
        OpenPGPApi api = new JcaOpenPGPApi(JslTestProvider.install());
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);

        OpenPGPMessageGenerator gen = api.signAndOrEncryptMessage();
        gen.addSigningKey(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream mOut = gen.open(bOut);
        mOut.write(PLAINTEXT);
        mOut.close();

        return bOut.toByteArray();
    }

    /**
     * A message whose signature packet precedes the literal data instead of being announced by a
     * one-pass packet - the shape {@code OpenPGPMessageInputStream.PrefixedSignatures} handles.
     */
    private byte[] prefixedSignedMessage()
        throws Exception
    {
        OpenPGPApi api = new JcaOpenPGPApi(JslTestProvider.install());
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.ALICE_KEY);

        List<OpenPGPSignature.OpenPGPDocumentSignature> signatures = api.createDetachedSignature()
            .addSigningKey(key)
            .sign(new ByteArrayInputStream(PLAINTEXT));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        signatures.get(0).getSignature().encode(pOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(pOut, PGPLiteralData.BINARY, "", PLAINTEXT.length, new Date());
        litOut.write(PLAINTEXT);
        litGen.close();

        pOut.close();

        return bOut.toByteArray();
    }

    public static void main(String[] args)
    {
        JslTestProvider.install();

        runTest(new OpenPGPConfiguredPolicyTest());
    }
}
