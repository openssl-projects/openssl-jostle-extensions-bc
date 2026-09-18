// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.util
{
    requires transitive org.bouncycastle.jsl.core;

    exports org.bouncycastle.jsl.asn1.bsi;
    exports org.bouncycastle.jsl.asn1.cmc;
    exports org.bouncycastle.jsl.asn1.cmp;
    exports org.bouncycastle.jsl.asn1.cms;
    exports org.bouncycastle.jsl.asn1.cms.ecc;
    exports org.bouncycastle.jsl.asn1.crmf;
    exports org.bouncycastle.jsl.asn1.dvcs;
    exports org.bouncycastle.jsl.asn1.eac;
    exports org.bouncycastle.jsl.asn1.esf;
    exports org.bouncycastle.jsl.asn1.ess;
    exports org.bouncycastle.jsl.asn1.est;
    exports org.bouncycastle.jsl.asn1.icao;
    exports org.bouncycastle.jsl.asn1.isara;
    exports org.bouncycastle.jsl.asn1.isismtt;
    exports org.bouncycastle.jsl.asn1.isismtt.ocsp;
    exports org.bouncycastle.jsl.asn1.isismtt.x509;
    exports org.bouncycastle.jsl.asn1.kisa;
    exports org.bouncycastle.jsl.asn1.microsoft;
    exports org.bouncycastle.jsl.asn1.mod;
    exports org.bouncycastle.jsl.asn1.mozilla;
    exports org.bouncycastle.jsl.asn1.nsri;
    exports org.bouncycastle.jsl.asn1.ntt;
    exports org.bouncycastle.jsl.asn1.smime;
    exports org.bouncycastle.jsl.asn1.tsp;
    exports org.bouncycastle.jsl.cbor;
    exports org.bouncycastle.jsl.cbor.c509;
    exports org.bouncycastle.jsl.oer;
    exports org.bouncycastle.jsl.oer.its;
    exports org.bouncycastle.jsl.oer.its.etsi102941;
    exports org.bouncycastle.jsl.oer.its.etsi102941.basetypes;
    exports org.bouncycastle.jsl.oer.its.etsi103097;
    exports org.bouncycastle.jsl.oer.its.etsi103097.extension;
    exports org.bouncycastle.jsl.oer.its.ieee1609dot2;
    exports org.bouncycastle.jsl.oer.its.ieee1609dot2.basetypes;
    exports org.bouncycastle.jsl.oer.its.ieee1609dot2dot1;
    exports org.bouncycastle.jsl.oer.its.template.etsi102941;
    exports org.bouncycastle.jsl.oer.its.template.etsi102941.basetypes;
    exports org.bouncycastle.jsl.oer.its.template.etsi103097;
    exports org.bouncycastle.jsl.oer.its.template.etsi103097.extension;
    exports org.bouncycastle.jsl.oer.its.template.ieee1609dot2;
    exports org.bouncycastle.jsl.oer.its.template.ieee1609dot2.basetypes;
    exports org.bouncycastle.jsl.oer.its.template.ieee1609dot2dot1;
}
