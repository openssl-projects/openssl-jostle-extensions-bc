// `requires transitive` means types of that module appear in this module's exported API,
// as measured by jdeps over the built jar.
module org.bouncycastle.jsl.mail
{
    requires transitive java.datatransfer;
    requires transitive org.bouncycastle.jsl.core;
    requires transitive org.bouncycastle.jsl.pkix;
    requires transitive org.bouncycastle.jsl.util;

    // javax.mail and javax.activation go by these four names depending on the artifact
    // used; a hard requires on any one of them breaks the rest. Optional at run time.
    requires static mail;
    requires static java.mail;
    requires static activation;
    requires static java.activation;

    exports org.bouncycastle.jsl.mail.smime;
    exports org.bouncycastle.jsl.mail.smime.examples;
    exports org.bouncycastle.jsl.mail.smime.handlers;
    exports org.bouncycastle.jsl.mail.smime.util;
    exports org.bouncycastle.jsl.mail.smime.validator;
}
