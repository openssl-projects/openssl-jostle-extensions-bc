package org.bouncycastle.jsl.math.ec.endo;

import org.bouncycastle.jsl.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
