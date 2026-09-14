// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.tls
{
    requires java.logging;
    requires org.bouncycastle.jsl.util;
    requires transitive org.bouncycastle.jsl.core;
    requires transitive org.openssl.jostle.prov;

    exports org.bouncycastle.jsse;
    exports org.bouncycastle.jsse.java.security;
    exports org.bouncycastle.jsse.provider;
    exports org.bouncycastle.jsse.util;
    exports org.bouncycastle.tls;
    exports org.bouncycastle.tls.crypto;
    exports org.bouncycastle.tls.crypto.impl;
    exports org.bouncycastle.tls.crypto.impl.jcajce;
    exports org.bouncycastle.tls.crypto.impl.jcajce.srp;

    provides java.security.Provider with org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
}
