package org.bouncycastle.jsl.crypto.constraints;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jsl.crypto.CryptoServiceProperties;
import org.bouncycastle.jsl.crypto.params.DHParameters;
import org.bouncycastle.jsl.crypto.params.DSAParameters;
import org.bouncycastle.jsl.crypto.params.RSAKeyParameters;
import org.bouncycastle.jsl.util.Strings;

/**
 * The part of bc-java's ConstraintUtils that the constraints in this library use. Upstream's class also
 * computes bits of security from its lightweight parameter classes, which this library does not carry.
 */
public class ConstraintUtils
{
    /**
     * The service names under which the quantum-vulnerable public-key algorithms report to the
     * constraints framework (upper-cased).
     */
    private static final Set<String> QUANTUM_VULNERABLE_SERVICES = new HashSet<String>();

    static
    {
        String[] names = new String[]{
            "RSA", "RSAKem", "RSAKeyGen",
            "DSA", "DSAKeyGen",
            "DH", "DHU", "DHB", "DHKeyGen", "DHBasicKeyGen", "MQV",
            "ECDH", "ECCDH", "ECCDHU", "ECMQV", "ECDSA", "ECNR", "ECGOST3410", "ECIESKem", "ECVKO", "ECCSI", "ECKeyGen",
            "GOST3410", "GOST3410KeyGen",
            "SM2", "SM2KE", "SM2KeyGen",
            "X25519", "X25519KeyGen", "X448", "X448KeyGen",
            "Ed25519", "Ed25519KeyGen", "Ed448", "Ed448KeyGen",
            "ElGamalKeyGen", "CramerShoup", "CramerShoupKeyGen",
            "NaccacheStern", "NaccacheStern KeyGen",
            "DSTU4145", "BIP340"
        };

        for (int i = 0; i != names.length; i++)
        {
            QUANTUM_VULNERABLE_SERVICES.add(Strings.toUpperCase(names[i]));
        }
    }

    /**
     * Return true if the service is one of the quantum-vulnerable public-key algorithms: the
     * integer factorisation and discrete logarithm schemes NIST IR 8547 deprecates after 2030 and
     * disallows after 2035 (RSA, DSA, DH/MQV, ECDSA/ECDH and their variants, EdDSA, X25519/X448,
     * ElGamal, Cramer-Shoup, Naccache-Stern and the KEMs and key agreements built on them). The decision is made on the key or
     * domain parameters the service reports where it reports any, and otherwise on its name. The
     * post-quantum algorithms and symmetric services are never quantum-vulnerable.
     *
     * @param service the service properties passed to the constraint.
     * @return true if the service relies on a quantum-vulnerable public-key algorithm, false otherwise.
     */
    public static boolean isQuantumVulnerable(CryptoServiceProperties service)
    {
        Object params = service.getParams();

        // Upstream also tests for its lightweight EC, EdDSA, XDH, ElGamal, GOST, Cramer-Shoup and
        // Naccache-Stern parameter classes. This library carries none of them: those services report by name.
        if (params instanceof RSAKeyParameters
            || params instanceof DSAParameters || params instanceof DHParameters)
        {
            return true;
        }

        String name = service.getServiceName();

        return name != null && QUANTUM_VULNERABLE_SERVICES.contains(Strings.toUpperCase(name));
    }
}
