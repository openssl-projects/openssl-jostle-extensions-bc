// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.pg
{
    requires java.logging;
    requires org.bouncycastle.jsl.util;
    requires transitive org.bouncycastle.jsl.core;
    requires org.openssl.jostle.prov;

    exports org.bouncycastle.apache.bzip2;
    exports org.bouncycastle.bcpg;
    exports org.bouncycastle.bcpg.attr;
    exports org.bouncycastle.bcpg.sig;
    exports org.bouncycastle.gpg;
    exports org.bouncycastle.gpg.keybox;
    exports org.bouncycastle.gpg.keybox.jcajce;
    exports org.bouncycastle.openpgp;
    exports org.bouncycastle.openpgp.api;
    exports org.bouncycastle.openpgp.api.exception;
    exports org.bouncycastle.openpgp.api.jcajce;
    exports org.bouncycastle.openpgp.api.util;
    exports org.bouncycastle.openpgp.jcajce;
    exports org.bouncycastle.openpgp.operator;
    exports org.bouncycastle.openpgp.operator.jcajce;
}
