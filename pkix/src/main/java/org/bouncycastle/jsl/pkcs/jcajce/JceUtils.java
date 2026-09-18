package org.bouncycastle.jsl.pkcs.jcajce;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jsl.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jsl.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jsl.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jsl.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jsl.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jsl.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jsl.jcajce.util.JcaJceHelper;

class JceUtils
{
    private static final Map PRFS = new HashMap();

    /**
     * PBES2 encryption schemes whose OID names a CBC mode, mapped to the JCA transformation that
     * spells out the padding.
     * <p>
     * The scheme OID does not tell a JCA provider to pad. RFC 8018 sec. B.2.5 defines the PBES2
     * AES-CBC scheme WITH PKCS#5 padding, but nothing requires a provider to infer that from the
     * algorithm OID used as a transformation name, and providers disagree: BouncyCastle pads,
     * while SunJCE and JSL both return a raw CBC cipher (measured 2026-09-08 - 30 bytes in gives
     * IllegalBlockSizeException on SunJCE and JSL, 32 bytes out on BC).
     * <p>
     * The OIDs here DO resolve on JSL, so the bare-OID lookup succeeds and hands back an unpadded
     * cipher; the failure then lands at doFinal as "data not block size aligned", not at
     * getInstance. Naming the transformation is therefore what changes the outcome - this is not a
     * fallback that only fires for an absent algorithm.
     * <p>
     * bc-java already does exactly this in the sibling layers: see CIPHER_ALG_NAMES in
     * cms.jcajce.EnvelopedDataHelper and cert.crmf.jcajce.CRMFHelper, each carrying its own copy.
     * This is the third, and it is why CMS AES-CBC works here while PBES2 did not.
     */
    private static final Map CIPHER_ALG_NAMES = new HashMap();

    static
    {
        PRFS.put(PKCSObjectIdentifiers.id_hmacWithSHA1, "PBKDF2withHMACSHA1");
        PRFS.put(PKCSObjectIdentifiers.id_hmacWithSHA256, "PBKDF2withHMACSHA256");
        PRFS.put(PKCSObjectIdentifiers.id_hmacWithSHA512, "PBKDF2withHMACSHA512");
        PRFS.put(PKCSObjectIdentifiers.id_hmacWithSHA224, "PBKDF2withHMACSHA224");
        PRFS.put(PKCSObjectIdentifiers.id_hmacWithSHA384, "PBKDF2withHMACSHA384");
        PRFS.put(NISTObjectIdentifiers.id_hmacWithSHA3_224, "PBKDF2withHMACSHA3-224");
        PRFS.put(NISTObjectIdentifiers.id_hmacWithSHA3_256, "PBKDF2withHMACSHA3-256");
        PRFS.put(NISTObjectIdentifiers.id_hmacWithSHA3_384, "PBKDF2withHMACSHA3-384");
        PRFS.put(NISTObjectIdentifiers.id_hmacWithSHA3_512, "PBKDF2withHMACSHA3-512");
        PRFS.put(CryptoProObjectIdentifiers.gostR3411Hmac, "PBKDF2withHMACGOST3411");

        CIPHER_ALG_NAMES.put(NISTObjectIdentifiers.id_aes128_CBC, "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(NISTObjectIdentifiers.id_aes192_CBC, "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(NISTObjectIdentifiers.id_aes256_CBC, "AES/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers.des_EDE3_CBC, "DESEDE/CBC/PKCS5Padding");
        CIPHER_ALG_NAMES.put(PKCSObjectIdentifiers.RC2_CBC, "RC2/CBC/PKCS5Padding");
    }

    /**
     * A Cipher for a PBES2 encryption scheme, naming the padded transformation where the scheme
     * has one and falling back to the bare OID otherwise.
     * <p>
     * Only NoSuchAlgorithmException falls through, mirroring EnvelopedDataHelper.createCipher. A
     * NoSuchPaddingException is deliberately NOT caught: a provider that serves the cipher but not
     * the padding should surface that, because falling back to the OID there would hand the caller
     * a raw cipher and reintroduce the very bug this table fixes.
     */
    static Cipher createCipher(JcaJceHelper helper, ASN1ObjectIdentifier algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        String cipherName = (String)CIPHER_ALG_NAMES.get(algorithm);

        if (cipherName != null)
        {
            try
            {
                return helper.createCipher(cipherName);
            }
            catch (NoSuchAlgorithmException e)
            {
                // fall through to the OID
            }
        }

        return helper.createCipher(algorithm.getId());
    }

    /**
     * Derive a PBKDF2 key for an EXPLICIT prf, naming the per-digest factory rather than relying on
     * the provider to read the prf out of a key spec.
     * <p>
     * A provider reached by the bare "PBKDF2" name or by the id-PBKDF2 OID is handed a
     * {@code PBKDF2KeySpec} and may not recognise it: it is a {@code PBEKeySpec} subclass, and a
     * provider that only understands its own spec type falls back to the RFC 8018 sec. A.2 default
     * of HMAC-SHA1 - silently deriving the WRONG KEY for every other prf. Measured on JSL
     * 2026-09-09: the OID and bare-name factories both returned the HMAC-SHA1 key whether the spec
     * said SHA-1 or SHA-256. The caller then finds out at BadPaddingException, or not at all where
     * the same wrong key is used to both write and verify.
     * <p>
     * Naming the factory removes the question. This is what
     * {@code JcePKCSPBEOutputEncryptorBuilder} already does on the encrypt side and what
     * {@code cms.jcajce.EnvelopedDataHelper} does for CMS; the PBES2 decrypt path and PBMAC1 were
     * the two outliers.
     * <p>
     * The fallback keeps the previous behaviour for a provider that serves ONLY the OID or bare
     * name and does honour the spec, so nothing that worked before stops working. An unmappable
     * prf lands there too, which is why IllegalStateException is caught: {@link #getAlgorithm}
     * throws it rather than returning null.
     *
     * @param fallback the factory the caller already resolved, used only if the named one is absent.
     */
    static SecretKey derivePbkdf2(JcaJceHelper helper, SecretKeyFactory fallback, char[] password,
        byte[] salt, int iterationCount, int keySizeInBits, AlgorithmIdentifier prf)
        throws GeneralSecurityException
    {
        try
        {
            SecretKeyFactory named = helper.createSecretKeyFactory(getAlgorithm(prf.getAlgorithm()));

            return named.generateSecret(new PBEKeySpec(password, salt, iterationCount, keySizeInBits));
        }
        catch (NoSuchAlgorithmException e)
        {
            // the provider does not serve the per-digest name; fall through
        }
        catch (IllegalStateException e)
        {
            // getAlgorithm has no mapping for this prf; fall through
        }

        return fallback.generateSecret(
            new PBKDF2KeySpec(password, salt, iterationCount, keySizeInBits, prf));
    }

    static String getAlgorithm(ASN1ObjectIdentifier algorithm)
    {
        if (!PRFS.containsKey(algorithm))
        {
            throw new IllegalStateException("no prf for algorithm: " + algorithm);
        }

        return ((String)PRFS.get(algorithm));
    }
}
