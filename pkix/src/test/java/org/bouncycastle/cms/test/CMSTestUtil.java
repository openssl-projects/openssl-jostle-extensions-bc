package org.bouncycastle.cms.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.bouncycastle.util.encoders.Base64;

public class CMSTestUtil
{
    public static SecureRandom     rand;
    public static KeyPairGenerator kpg;
    public static KeyPairGenerator kpg_2048;

    public static KeyPairGenerator gostKpg;
    public static KeyPairGenerator dsaKpg;
    public static KeyPairGenerator dhKpg;
    public static KeyPairGenerator ecGostKpg;
    public static KeyPairGenerator ecGost2012_256Kpg;
    public static KeyPairGenerator ecDsaKpg;
    public static KeyPairGenerator ed25519Kpg;
    public static KeyPairGenerator ed448Kpg;
    public static KeyPairGenerator mlDsa44Kpg;
    public static KeyPairGenerator mlDsa65Kpg;
    public static KeyPairGenerator mlDsa87Kpg;
    public static KeyPairGenerator mlKem512Kpg;
    public static KeyPairGenerator mlKem768Kpg;
    public static KeyPairGenerator mlKem1024Kpg;
    public static KeyPairGenerator ntruKpg;
    public static KeyPairGenerator slhDsa_Sha2_128f_Kpg;
    public static KeyPairGenerator slhDsa_Sha2_128s_Kpg;
    public static KeyPairGenerator slhDsa_Sha2_192f_Kpg;
    public static KeyPairGenerator slhDsa_Sha2_192s_Kpg;
    public static KeyPairGenerator slhDsa_Sha2_256f_Kpg;
    public static KeyPairGenerator slhDsa_Sha2_256s_Kpg;
    public static KeyPairGenerator slhDsa_Shake_128f_Kpg;
    public static KeyPairGenerator slhDsa_Shake_128s_Kpg;
    public static KeyPairGenerator slhDsa_Shake_192f_Kpg;
    public static KeyPairGenerator slhDsa_Shake_192s_Kpg;
    public static KeyPairGenerator slhDsa_Shake_256f_Kpg;
    public static KeyPairGenerator slhDsa_Shake_256s_Kpg;
    public static KeyGenerator     aes192kg;
    public static KeyGenerator     desede128kg;
    public static KeyGenerator     desede192kg;
    public static KeyGenerator     rc240kg;
    public static KeyGenerator     rc264kg;
    public static KeyGenerator     rc2128kg;
    public static KeyGenerator     aesKg;
    public static KeyGenerator     seedKg;
    public static KeyGenerator     camelliaKg;
    public static BigInteger       serialNumber;

    private static boolean aeadAvailable = false;

    public static final boolean DEBUG = true;

    private static byte[]  attrCert = Base64.decode(
                "MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2"
              + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS"
              + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2"
              + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0"
              + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn"
              + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw"
              + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY"
              + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs"
              + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K"
              + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0"
              + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j"
              + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw"
              + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg"
              + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl"
              + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt"
              + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0"
              + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8"
              + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl"
              + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ"
              + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct"
              + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3"
              + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1"
              + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy"
              + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6"
              + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov"
              + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz"
              + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0"
              + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46"
              + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+"
              + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y"
              + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv"
              + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0"
              + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph"
              + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj"
              + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+"
              + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA"
              + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr"
              + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3"
              + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");
    
    static
    {
        try
        {
            java.security.Security.addProvider(new JostleProvider());

            try
            {
                CMSTestUtil.class.getClassLoader().loadClass("javax.crypto.spec.GCMParameterSpec");
                aeadAvailable = true;
            }
            catch (ClassNotFoundException e)
            {
            }

            rand = new SecureRandom();

            kpg  = KeyPairGenerator.getInstance("RSA", "JSL");
            kpg.initialize(1024, rand);

            kpg_2048  = KeyPairGenerator.getInstance("RSA", "JSL");
            kpg_2048.initialize(2048, rand);

            // GOST/ECGOST/NTRU are not provided by JSL — pruned for this migration.
            // DSA is now provided by JSL; initialize from fixed domain params to avoid slow
            // per-run parameter generation. bc-java's classic 512-bit (L=512/N=160) params are
            // rejected by OpenSSL ("ffc_validate_LN: bad ffc parameters"), so use a valid
            // FIPS 186 L=2048/N=256 group instead.
            dsaKpg = KeyPairGenerator.getInstance("DSA", "JSL");
            DSAParameterSpec dsaSpec = new DSAParameterSpec(
                        new BigInteger("19907565429699108605275272201029585048408596875322885479894746357284399280166582585765686106984881564412104574550300138070457571247860071221477838908456619458861228607337783502463731542532762694884945833487703809747602316770156332911602554652015599330415547625485320715155417793124370708600251872088280352141538973303229601775394226588766869167763895454981975693019798760300986573918169305343915525337885310799725408674995067392159515122937325375425294368275646171085327971643626041043161733317587273013543328773565906825915000132384966127230722893125496365396771075916620559716104409563919651186177896251297550794463"),
                        new BigInteger("73315037449468766965231205574813280361082575942612732494865930830281743537203"),
                        new BigInteger("11729870206115473869077340490323893837979099349513998828557803452877876130949735409133803271873340669391852605151712703657982845013304921971707183304685261131770165774661552205488167513265901856190008339942833228402833809306379534091156558160025008117934882285175414836141408172486231443864227770348662642922041919709867836795881371501477523655842615214468339347999175931075419958018636942859999909821982988738453383338889805734026748173513308029682799911346828789008708940295443917831058836597136609245596552427704787364349851398040443910165249817689198981342112503388387320981520316840946186610002873930888774364210"));
            dsaKpg.initialize(dsaSpec, new SecureRandom());

            // DH is now provided by JSL; reuse the DSA prime/generator as the DH group
            // (matching bc-java), which is a valid 2048-bit finite-field group.
            dhKpg = KeyPairGenerator.getInstance("DH", "JSL");
            dhKpg.initialize(new DHParameterSpec(dsaSpec.getP(), dsaSpec.getG()), new SecureRandom());

            ecDsaKpg = KeyPairGenerator.getInstance("EC", "JSL");
            ecDsaKpg.initialize(256, new SecureRandom());

            ed25519Kpg = KeyPairGenerator.getInstance("Ed25519", "JSL");
            ed448Kpg = KeyPairGenerator.getInstance("Ed448", "JSL");

            mlDsa44Kpg = KeyPairGenerator.getInstance("ML-DSA-44", "JSL");
            mlDsa65Kpg = KeyPairGenerator.getInstance("ML-DSA-65", "JSL");
            mlDsa87Kpg = KeyPairGenerator.getInstance("ML-DSA-87", "JSL");

            mlKem512Kpg = KeyPairGenerator.getInstance("ML-KEM-512", "JSL");
            mlKem768Kpg = KeyPairGenerator.getInstance("ML-KEM-768", "JSL");
            mlKem1024Kpg = KeyPairGenerator.getInstance("ML-KEM-1024", "JSL");

            slhDsa_Sha2_128f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128F", "JSL");
            slhDsa_Sha2_128s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-128S", "JSL");
            slhDsa_Sha2_192f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-192F", "JSL");
            slhDsa_Sha2_192s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-192S", "JSL");
            slhDsa_Sha2_256f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-256F", "JSL");
            slhDsa_Sha2_256s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHA2-256S", "JSL");
            slhDsa_Shake_128f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-128F", "JSL");
            slhDsa_Shake_128s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-128S", "JSL");
            slhDsa_Shake_192f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-192F", "JSL");
            slhDsa_Shake_192s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-192S", "JSL");
            slhDsa_Shake_256f_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-256F", "JSL");
            slhDsa_Shake_256s_Kpg = KeyPairGenerator.getInstance("SLH-DSA-SHAKE-256S", "JSL");

            // Symmetric content-encryption keygens are not exercised by the SignedData
            // tests; tolerate individually any algorithm the JSL provider does not expose
            // (RC2/SEED are absent; Camellia is Cipher-only) so class init still completes.
            try { aes192kg = KeyGenerator.getInstance("AES", "JSL"); aes192kg.init(192, rand); } catch (Exception e) { }
            try { desede128kg = KeyGenerator.getInstance("DESEDE", "JSL"); desede128kg.init(192, rand); } catch (Exception e) { }
            try { desede192kg = KeyGenerator.getInstance("DESEDE", "JSL"); desede192kg.init(168, rand); } catch (Exception e) { }
            try { aesKg = KeyGenerator.getInstance("AES", "JSL"); } catch (Exception e) { }
            try { camelliaKg = KeyGenerator.getInstance("Camellia", "JSL"); } catch (Exception e) { }

            serialNumber = new BigInteger("1");
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.toString());
        }
    }

    public static boolean isAeadAvailable()
    {
        return aeadAvailable;
    }

    public static String dumpBase64(
        byte[]  data)
    {
        StringBuilder    buf = new StringBuilder();
        
        data = Base64.encode(data);
        
        for (int i = 0; i < data.length; i += 64)
        {
            if (i + 64 < data.length)
            {
                buf.append(new String(data, i, 64));
            }
            else
            {
                buf.append(new String(data, i, data.length - i));
            }
            buf.append('\n');
        }
        
        return buf.toString();
    }

    public static X509AttributeCertificateHolder getAttributeCertificate()
        throws Exception
    {
        return  new X509AttributeCertificateHolder(CMSTestUtil.attrCert);
    }

    public static KeyPair makeKeyPair()
    {
        return kpg.generateKeyPair();
    }

    public static KeyPair makeKeyPair_2048()
    {
        return kpg_2048.generateKeyPair();
    }

    public static KeyPair makeGostKeyPair()
    {
        return gostKpg.generateKeyPair();
    }

    public static KeyPair makeDsaKeyPair()
    {
        return dsaKpg.generateKeyPair();
    }

    public static KeyPair makeEd25519KeyPair()
    {
        return ed25519Kpg.generateKeyPair();
    }

    public static KeyPair makeEd448KeyPair()
    {
        return ed448Kpg.generateKeyPair();
    }

    public static KeyPair makeEcDsaKeyPair()
    {
        return ecDsaKpg.generateKeyPair();
    }

    public static KeyPair makeDhKeyPair()
    {
        return dhKpg.generateKeyPair();
    }

    public static KeyPair makeEcGostKeyPair()
    {
        return ecGostKpg.generateKeyPair();
    }

    public static KeyPair makeEcGost2012_256KeyPair()
    {
        return ecGost2012_256Kpg.generateKeyPair();
    }

    public static KeyPair makeNtruKeyPair()
    {
        return ntruKpg.generateKeyPair();
    }

    public static KeyPair makeMLKem512KeyPair()
    {
        return mlKem512Kpg.generateKeyPair();
    }

    public static KeyPair makeMLKem768KeyPair()
    {
        return mlKem768Kpg.generateKeyPair();
    }

    public static KeyPair makeMLKem1024KeyPair()
    {
        return mlKem1024Kpg.generateKeyPair();
    }

    public static KeyPair makeMLDsa44KeyPair()
    {
        return mlDsa44Kpg.generateKeyPair();
    }

    public static KeyPair makeMLDsa65KeyPair()
    {
        return mlDsa65Kpg.generateKeyPair();
    }

    public static KeyPair makeMLDsa87KeyPair()
    {
        return mlDsa87Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_128f_KeyPair()
    {
        return slhDsa_Sha2_128f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_128s_KeyPair()
    {
        return slhDsa_Sha2_128s_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_192f_KeyPair()
    {
        return slhDsa_Sha2_192f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_192s_KeyPair()
    {
        return slhDsa_Sha2_192s_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_256f_KeyPair()
    {
        return slhDsa_Sha2_256f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Sha2_256s_KeyPair()
    {
        return slhDsa_Sha2_256s_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_128f_KeyPair()
    {
        return slhDsa_Shake_128f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_128s_KeyPair()
    {
        return slhDsa_Shake_128s_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_192f_KeyPair()
    {
        return slhDsa_Shake_192f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_192s_KeyPair()
    {
        return slhDsa_Shake_192s_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_256f_KeyPair()
    {
        return slhDsa_Shake_256f_Kpg.generateKeyPair();
    }

    public static KeyPair makeSlhDsa_Shake_256s_KeyPair()
    {
        return slhDsa_Shake_256s_Kpg.generateKeyPair();
    }

    public static SecretKey makeDesede128Key()
    {
        return desede128kg.generateKey();
    }

    public static SecretKey makeAES192Key()
    {
        return aes192kg.generateKey();
    }

    public static SecretKey makeDesede192Key()
    {
        return desede192kg.generateKey();
    }

    public static SecretKey makeRC240Key()
    {
        return rc240kg.generateKey();
    }

    public static SecretKey makeRC264Key()
    {
        return rc264kg.generateKey();
    }

    public static SecretKey makeRC2128Key()
    {
        return rc2128kg.generateKey();
    }

    public static SecretKey makeSEEDKey()
    {
        return seedKg.generateKey();
    }

    public static SecretKey makeAESKey(int keySize)
    {
        aesKg.init(keySize);
        return aesKg.generateKey();
    }

    public static SecretKey makeCamelliaKey(int keySize)
    {
        camelliaKg.init(keySize);
        return camelliaKg.generateKey();
    }

    public static X509Certificate makeCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeOaepCertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeOaepCertificate(_subKP, _subDN, _issKP, _issDN, false);
    }

    public static X509Certificate makeCACertificate(KeyPair _subKP,
            String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, true);
    }

    public static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey  subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v1CertificateBuilder v1CertGen = new JcaX509v1CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        X509Certificate _cert = new JcaX509CertificateConverter().getCertificate(v1CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        PublicKey  subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();
        
        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub);

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        X509Certificate _cert = new JcaX509CertificateConverter().getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, AlgorithmIdentifier keyAlgID)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();
        SubjectPublicKeyInfo subPub = SubjectPublicKeyInfo.getInstance(subKP.getPublic().getEncoded());

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(keyAlgID, subPub.parsePublicKey()));

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(false));

        X509Certificate _cert = new JcaX509CertificateConverter().getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    public static X509Certificate makeOaepCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca)
        throws GeneralSecurityException, IOException, OperatorCreationException
    {

        SubjectPublicKeyInfo  subPub  = SubjectPublicKeyInfo.getInstance(subKP.getPublic().getEncoded());
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, new RSAESOAEPparams()), subPub.parsePublicKey()));

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub);

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca));

        X509Certificate _cert = new JcaX509CertificateConverter().getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }

    private static JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub)
    {
        /*
         * NOTE: Current ALL test certificates are issued under a SHA1withRSA root, so this list is mostly
         * redundant (and also incomplete in that it doesn't handle EdDSA or ML-DSA issuers).
         */
        JcaContentSignerBuilder contentSignerBuilder;
        if (issPub instanceof RSAPublicKey)
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1WithRSA");
        }
        else if (issPub.getAlgorithm().equals("DSA"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withDSA");
        }
        else if (issPub.getAlgorithm().equals("ECDSA"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA1withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECGOST3410"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411withECGOST3410");
        }
        else if (issPub.getAlgorithm().equals("GOST3410"))
        {
            contentSignerBuilder = new JcaContentSignerBuilder("GOST3411WithGOST3410");
        }
        else
        {
            throw new UnsupportedOperationException("Algorithm handlers incomplete");
        }

        contentSignerBuilder.setProvider(JostleProvider.PROVIDER_NAME);

        return contentSignerBuilder;
    }

    public static X509CRL makeCrl(KeyPair pair)
        throws Exception
    {
        Date                 now = new Date();
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(new X500Name("CN=Test CA"), now);
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

        crlGen.setNextUpdate(new Date(now.getTime() + 100000));

        crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(pair.getPublic()));

        return new JcaX509CRLConverter().getCRL(crlGen.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("JSL").build(pair.getPrivate())));
    }

    /*  
     *  
     *  INTERNAL METHODS
     *  
     */ 

    private static final X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator());

    private static AuthorityKeyIdentifier createAuthorityKeyId(
        PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()));
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        SubjectPublicKeyInfo _pubKey)
        throws IOException
    {
        return extUtils.createSubjectKeyIdentifier(_pubKey);
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        PublicKey _pubKey)
        throws IOException
    {
        return extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()));
    }

    private static BigInteger allocateSerialNumber()
    {
        BigInteger _tmp = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return _tmp;
    }
    
    public static byte[] streamToByteArray(
        InputStream in) 
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        return bOut.toByteArray();
    }
}
