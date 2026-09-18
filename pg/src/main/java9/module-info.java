// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.pg
{
    requires java.logging;
    requires org.bouncycastle.jsl.util;
    requires transitive org.bouncycastle.jsl.core;
    requires org.openssl.jostle.prov;

    exports org.bouncycastle.jsl.apache.bzip2;
    exports org.bouncycastle.jsl.bcpg;
    exports org.bouncycastle.jsl.bcpg.attr;
    exports org.bouncycastle.jsl.bcpg.sig;
    exports org.bouncycastle.jsl.gpg;
    exports org.bouncycastle.jsl.gpg.keybox;
    exports org.bouncycastle.jsl.gpg.keybox.jcajce;
    exports org.bouncycastle.jsl.openpgp;
    exports org.bouncycastle.jsl.openpgp.api;
    exports org.bouncycastle.jsl.openpgp.api.exception;
    exports org.bouncycastle.jsl.openpgp.api.jcajce;
    exports org.bouncycastle.jsl.openpgp.api.util;
    exports org.bouncycastle.jsl.openpgp.jcajce;
    exports org.bouncycastle.jsl.openpgp.operator;
    exports org.bouncycastle.jsl.openpgp.operator.jcajce;
}
