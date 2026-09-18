// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.pkix
{
    requires java.logging;
    requires java.naming;
    requires transitive org.bouncycastle.jsl.core;
    requires transitive org.bouncycastle.jsl.util;
    requires org.openssl.jostle.prov;

    exports org.bouncycastle.jsl.cades;
    exports org.bouncycastle.jsl.cert;
    exports org.bouncycastle.jsl.cert.cmp;
    exports org.bouncycastle.jsl.cert.crmf;
    exports org.bouncycastle.jsl.cert.crmf.jcajce;
    exports org.bouncycastle.jsl.cert.ct;
    exports org.bouncycastle.jsl.cert.dane;
    exports org.bouncycastle.jsl.cert.dane.fetcher;
    exports org.bouncycastle.jsl.cert.jcajce;
    exports org.bouncycastle.jsl.cert.ocsp;
    exports org.bouncycastle.jsl.cert.ocsp.jcajce;
    exports org.bouncycastle.jsl.cert.path;
    exports org.bouncycastle.jsl.cert.path.validations;
    exports org.bouncycastle.jsl.cert.plants;
    exports org.bouncycastle.jsl.cert.plants.jcajce;
    exports org.bouncycastle.jsl.cert.selector;
    exports org.bouncycastle.jsl.cert.selector.jcajce;
    exports org.bouncycastle.jsl.cmc;
    exports org.bouncycastle.jsl.cms;
    exports org.bouncycastle.jsl.cms.jcajce;
    exports org.bouncycastle.jsl.dvcs;
    exports org.bouncycastle.jsl.eac;
    exports org.bouncycastle.jsl.eac.jcajce;
    exports org.bouncycastle.jsl.eac.operator;
    exports org.bouncycastle.jsl.eac.operator.jcajce;
    exports org.bouncycastle.jsl.est;
    exports org.bouncycastle.jsl.est.jcajce;
    exports org.bouncycastle.jsl.its;
    exports org.bouncycastle.jsl.its.jcajce;
    exports org.bouncycastle.jsl.its.operator;
    exports org.bouncycastle.jsl.mime;
    exports org.bouncycastle.jsl.mime.encoding;
    exports org.bouncycastle.jsl.mime.smime;
    exports org.bouncycastle.jsl.mozilla;
    exports org.bouncycastle.jsl.mozilla.jcajce;
    exports org.bouncycastle.jsl.openssl;
    exports org.bouncycastle.jsl.openssl.jcajce;
    exports org.bouncycastle.jsl.operator;
    exports org.bouncycastle.jsl.operator.jcajce;
    exports org.bouncycastle.jsl.pkcs;
    exports org.bouncycastle.jsl.pkcs.jcajce;
    exports org.bouncycastle.jsl.pkcs.util;
    exports org.bouncycastle.jsl.pkix;
    exports org.bouncycastle.jsl.pkix.jcajce;
    exports org.bouncycastle.jsl.pkix.util;
    exports org.bouncycastle.jsl.pkix.util.filter;
    exports org.bouncycastle.jsl.tsp;
    exports org.bouncycastle.jsl.tsp.cms;
    exports org.bouncycastle.jsl.tsp.ers;
    exports org.bouncycastle.jsl.voms;
}
