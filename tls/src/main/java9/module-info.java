// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.tls
{
    requires java.logging;
    requires org.bouncycastle.jsl.util;
    requires transitive org.bouncycastle.jsl.core;
    requires transitive org.openssl.jostle.prov;

    exports org.bouncycastle.jsl.jsse;
    exports org.bouncycastle.jsl.jsse.java.security;
    exports org.bouncycastle.jsl.jsse.provider;
    exports org.bouncycastle.jsl.jsse.util;
    exports org.bouncycastle.jsl.tls;
    exports org.bouncycastle.jsl.tls.crypto;
    exports org.bouncycastle.jsl.tls.crypto.impl;
    exports org.bouncycastle.jsl.tls.crypto.impl.jcajce;
    exports org.bouncycastle.jsl.tls.crypto.impl.jcajce.srp;

    provides java.security.Provider with org.bouncycastle.jsl.jsse.provider.BouncyCastleJsseProvider;
}
