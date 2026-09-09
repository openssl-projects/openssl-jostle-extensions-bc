package org.bouncycastle.pkcs.jcajce;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.util.JcaJceHelper;

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

    static String getAlgorithm(ASN1ObjectIdentifier algorithm)
    {
        if (!PRFS.containsKey(algorithm))
        {
            throw new IllegalStateException("no prf for algorithm: " + algorithm);
        }

        return ((String)PRFS.get(algorithm));
    }
}
