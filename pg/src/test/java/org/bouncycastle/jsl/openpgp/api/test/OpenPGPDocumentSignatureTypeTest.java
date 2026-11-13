package org.bouncycastle.jsl.openpgp.api.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jsl.bcpg.BCPGOutputStream;
import org.bouncycastle.jsl.bcpg.HashAlgorithmTags;
import org.bouncycastle.jsl.bcpg.PacketFormat;
import org.bouncycastle.jsl.openpgp.OpenPGPTestKeys;
import org.bouncycastle.jsl.openpgp.PGPLiteralData;
import org.bouncycastle.jsl.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.jsl.openpgp.PGPOnePassSignature;
import org.bouncycastle.jsl.openpgp.PGPPublicKey;
import org.bouncycastle.jsl.openpgp.PGPSignature;
import org.bouncycastle.jsl.openpgp.PGPSignatureGenerator;
import org.bouncycastle.jsl.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.jsl.openpgp.api.OpenPGPApi;
import org.bouncycastle.jsl.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.jsl.openpgp.api.OpenPGPDetachedSignatureProcessor;
import org.bouncycastle.jsl.openpgp.api.OpenPGPKey;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageInputStream;
import org.bouncycastle.jsl.openpgp.api.OpenPGPMessageProcessor;
import org.bouncycastle.jsl.openpgp.api.OpenPGPSignature;
import org.bouncycastle.jsl.openpgp.api.jcajce.JcaOpenPGPApi;
import org.bouncycastle.jsl.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.jsl.util.Arrays;
import org.bouncycastle.jsl.util.Strings;
import org.bouncycastle.jsl.util.io.Streams;
import org.bouncycastle.jsl.util.test.SimpleTest;
import org.bouncycastle.jsl.test.JslTestProvider;

/**
 * Only a binary (0x00) or canonical text (0x01) document signature is a signature over a document
 * (RFC 9580, section 5.2.1). A genuine signature of any other type - a certification, a binding, a
 * revocation, a standalone signature - presented over the bytes it covers must not be reported valid
 * by the detached, one-pass or prefixed signature paths of the high-level API. On the one-pass path
 * the type announced by the One-Pass Signature packet must also match the Signature packet's.
 */
public class OpenPGPDocumentSignatureTypeTest
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

    private static final byte[] DOCUMENT = Strings.toUTF8ByteArray("Hello, World!\r\n");

    private static final int[] NON_DOCUMENT_TYPES = {
        PGPSignature.STAND_ALONE,
        PGPSignature.DEFAULT_CERTIFICATION,
        PGPSignature.NO_CERTIFICATION,
        PGPSignature.CASUAL_CERTIFICATION,
        PGPSignature.POSITIVE_CERTIFICATION,
        PGPSignature.SUBKEY_BINDING,
        PGPSignature.PRIMARYKEY_BINDING,
        PGPSignature.DIRECT_KEY,
        PGPSignature.KEY_REVOCATION,
        PGPSignature.SUBKEY_REVOCATION,
        PGPSignature.CERTIFICATION_REVOCATION,
        PGPSignature.TIMESTAMP
    };

    private static final int[] DOCUMENT_TYPES = {
        PGPSignature.BINARY_DOCUMENT,
        PGPSignature.CANONICAL_TEXT_DOCUMENT
    };

    private final OpenPGPApi api = new JcaOpenPGPApi(JslTestProvider.install());

    public String getName()
    {
        return "OpenPGPDocumentSignatureTypeTest";
    }

    public void performTest()
        throws Exception
    {
        // a FIPS module may serve none of these, or only some
        if (!JslTestProvider.supports("Signature.Ed25519", "KeyAgreement.X25519"))
        {
            return;
        }

        checkKey("v4", OpenPGPTestKeys.ALICE_KEY, OpenPGPTestKeys.ALICE_CERT);
        checkKey("v6", OpenPGPTestKeys.V6_KEY, OpenPGPTestKeys.V6_CERT);
    }

    private void checkKey(String label, String keyText, String certText)
        throws Exception
    {
        OpenPGPKey key = api.readKeyOrCertificate().parseKey(keyText);
        OpenPGPCertificate cert = api.readKeyOrCertificate().parseCertificate(certText);

        for (int i = 0; i != DOCUMENT_TYPES.length; i++)
        {
            int type = DOCUMENT_TYPES[i];
            Signed sig = sign(key, type);
            String desc = label + " type 0x" + Integer.toHexString(type);

            isTrue(desc + " detached should be valid", isOnlyValid(verifyDetached(cert, sig)));
            isTrue(desc + " one-pass should be valid", isOnlyValid(verifyInline(cert, sig, type, true)));
            isTrue(desc + " prefixed should be valid", isOnlyValid(verifyInline(cert, sig, type, false)));
        }

        for (int i = 0; i != NON_DOCUMENT_TYPES.length; i++)
        {
            int type = NON_DOCUMENT_TYPES[i];
            Signed sig = sign(key, type);
            String desc = label + " type 0x" + Integer.toHexString(type);

            isTrue(desc + " detached must not be valid", noneValid(verifyDetached(cert, sig)));
            isTrue(desc + " one-pass must not be valid", noneValid(verifyInline(cert, sig, type, true)));
            isTrue(desc + " prefixed must not be valid", noneValid(verifyInline(cert, sig, type, false)));
        }

        // a document signature behind a one-pass signature packet announcing a different type
        isTrue(label + " binary signature behind a certification OPS must not be valid",
            noneValid(verifyInline(cert, sign(key, PGPSignature.BINARY_DOCUMENT), PGPSignature.POSITIVE_CERTIFICATION, true)));
        isTrue(label + " binary signature behind a text OPS must not be valid",
            noneValid(verifyInline(cert, sign(key, PGPSignature.BINARY_DOCUMENT), PGPSignature.CANONICAL_TEXT_DOCUMENT, true)));
        isTrue(label + " text signature behind a binary OPS must not be valid",
            noneValid(verifyInline(cert, sign(key, PGPSignature.CANONICAL_TEXT_DOCUMENT), PGPSignature.BINARY_DOCUMENT, true)));
    }

    /**
     * Make a genuine signature of the given type by the key's signing key over DOCUMENT.
     */
    private Signed sign(OpenPGPKey key, int type)
        throws Exception
    {
        OpenPGPCertificate.OpenPGPComponentKey signingKey = (OpenPGPCertificate.OpenPGPComponentKey)key.getSigningKeys().get(0);
        PGPPublicKey pubKey = signingKey.getPGPPublicKey();

        PGPSignatureGenerator gen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(pubKey.getAlgorithm(), HashAlgorithmTags.SHA512).setProvider(JslTestProvider.name()), pubKey);
        gen.init(type, key.getSecretKey(signingKey).unlock().getKeyPair().getPrivateKey());

        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setIssuerFingerprint(false, pubKey);
        hashed.setSignatureCreationTime(true, new Date());
        gen.setHashedSubpackets(hashed.generate());

        PGPOnePassSignature ops = gen.generateOnePassVersion(false);

        gen.update(DOCUMENT);

        return new Signed(gen.generate(), ops.getEncoded());
    }

    private List<OpenPGPSignature.OpenPGPDocumentSignature> verifyDetached(OpenPGPCertificate cert, Signed signed)
        throws Exception
    {
        OpenPGPDetachedSignatureProcessor processor = api.verifyDetachedSignature();
        processor.addSignature(signed.sig);
        processor.addVerificationCertificate(cert);

        return processor.process(new ByteArrayInputStream(DOCUMENT));
    }

    /**
     * Verify sig over DOCUMENT as an inline message, either behind a one-pass signature packet announcing
     * opsType, or as a signature packet preceding the literal data.
     */
    private List<OpenPGPSignature.OpenPGPDocumentSignature> verifyInline(OpenPGPCertificate cert, Signed signed,
                                                                         int opsType, boolean onePass)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        if (onePass)
        {
            // the generator's own OPS packet (so a v6 salt matches) with its type octet set to opsType
            byte[] ops = Arrays.clone(signed.ops);
            isTrue("test setup: unexpected OPS packet layout", ops[1] == ops.length - 2 && (ops[2] == 3 || ops[2] == 6));
            ops[3] = (byte)opsType;
            bOut.write(ops);
        }
        else
        {
            signed.sig.encode(bOut);
        }

        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.CURRENT);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(pOut, PGPLiteralData.BINARY, "", DOCUMENT.length, new Date());
        litOut.write(DOCUMENT);
        litOut.close();

        if (onePass)
        {
            signed.sig.encode(pOut);
        }
        pOut.close();

        OpenPGPMessageProcessor processor = api.decryptAndOrVerifyMessage();
        processor.addVerificationCertificate(cert);

        OpenPGPMessageInputStream msgIn = processor.process(new ByteArrayInputStream(bOut.toByteArray()));
        Streams.drain((InputStream)msgIn);
        msgIn.close();

        return msgIn.getResult().getSignatures();
    }

    private boolean isOnlyValid(List<OpenPGPSignature.OpenPGPDocumentSignature> sigs)
        throws Exception
    {
        return sigs.size() == 1 && sigs.get(0).isValid();
    }

    private boolean noneValid(List<OpenPGPSignature.OpenPGPDocumentSignature> sigs)
        throws Exception
    {
        for (int i = 0; i != sigs.size(); i++)
        {
            OpenPGPSignature.OpenPGPDocumentSignature sig = sigs.get(i);
            if (sig.isTestedCorrect() ? sig.isValid() : false)
            {
                return false;
            }
        }
        return true;
    }

    private static class Signed
    {
        final PGPSignature sig;
        final byte[] ops;

        Signed(PGPSignature sig, byte[] ops)
        {
            this.sig = sig;
            this.ops = ops;
        }
    }

    public static void main(String[] args)
    {
        JslTestProvider.install();

        runTest(new OpenPGPDocumentSignatureTypeTest());
    }
}
