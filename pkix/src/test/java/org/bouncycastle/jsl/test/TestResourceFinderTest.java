package org.bouncycastle.jsl.test;

import java.io.File;
import java.io.IOException;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * The bc-test-data walk-up, checked without the data itself. The Windows runners run the same
 * checks on drive-letter paths, where the old string-trimming walk-up threw instead of ending.
 */
public class TestResourceFinderTest
{
    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void findsTheNearestDataDirectoryAbove()
        throws IOException
    {
        File data = tmp.newFolder("bc-test-data");
        File start = tmp.newFolder("a", "b", "c");

        Assert.assertEquals(data.getCanonicalFile(), TestResourceFinder.findDataDir(start).getCanonicalFile());
    }

    @Test
    public void endsAtTheRootWhenThereIsNone()
        throws IOException
    {
        File start = tmp.newFolder("x", "y");
        // A developer machine may hold a bc-test-data above the temporary directory; then this
        // case cannot be staged here.
        for (File dir = tmp.getRoot().getParentFile(); dir != null; dir = dir.getParentFile())
        {
            Assume.assumeFalse(new File(dir, "bc-test-data").isDirectory());
        }

        Assert.assertNull(TestResourceFinder.findDataDir(start));
    }
}
