package org.bouncycastle.jsl.test;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jsl.cert.plants.ListMerkleTreeNodeSource;
import org.bouncycastle.jsl.cert.plants.MerkleTreeHash;
import org.bouncycastle.jsl.cert.plants.MerkleTreePrimitives;
import org.bouncycastle.jsl.cert.plants.jcajce.JcaSha256MerkleTreeHash;
import org.bouncycastle.jsl.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Merkle tree subtree-inclusion proofs over JSL's SHA-256, covering the proof path only.
 * <p>
 * This is NOT a port of upstream's MerkleTreeCertificatesTest. That suite is 1888 lines and is
 * built on what this fork deletes - {@code cert.plants.bc.*} lightweight operators,
 * {@code crypto.digests.SHA256Digest} and {@code SHA384Digest},
 * {@code crypto.generators.ECKeyPairGenerator}, {@code Ed25519KeyPairGenerator} and
 * {@code MLDSAKeyPairGenerator}, and {@code BouncyCastleProvider} - so porting it would mean
 * rewriting it onto the Jca/Jce operators rather than migrating it.
 * <p>
 * Covered here: subtree-inclusion proof generation and verification over JSL's SHA-256, at
 * power-of-two and odd tree sizes.
 */
public class MerkleTreeProofPathTest
{
    @BeforeClass
    public static void installProvider()
        throws Exception
    {
        JslTestProvider.install();
    }

    private static MerkleTreeHash hash()
    {
        return new JcaSha256MerkleTreeHash(JslTestProvider.name());
    }

    private static List<byte[]> leafHashes(int n, MerkleTreeHash hash)
    {
        List<byte[]> hashes = new ArrayList<byte[]>();
        for (int i = 0; i != n; i++)
        {
            hashes.add(hash.hashLeaf(("entry-" + i).getBytes()));
        }
        return hashes;
    }

    /**
     * Every leaf of a power-of-two tree proves against the root.
     */
    @Test
    public void testEveryLeafProvesInAPowerOfTwoTree()
        throws Exception
    {
        assertEveryLeafProves(8);
    }

    /**
     * Every leaf of an odd-sized tree proves against the root. 5 leaves gives a 4+1 split at the
     * top and a ragged right-hand subtree, which a power-of-two size never exercises.
     */
    @Test
    public void testEveryLeafProvesInAnOddSizedTree()
        throws Exception
    {
        assertEveryLeafProves(5);
        assertEveryLeafProves(7);
    }

    /**
     * A single-leaf tree: the proof is empty and the root is the leaf hash.
     */
    @Test
    public void testSingleLeafTreeHasAnEmptyProof()
        throws Exception
    {
        MerkleTreeHash hash = hash();
        List<byte[]> leaves = leafHashes(1, hash);
        byte[] root = new ListMerkleTreeNodeSource(leaves, hash).getFullSubtreeHash(0, 1);

        List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(0, 0, 1, leaves, hash);

        assertEquals("a size-one subtree needs no sibling hashes", 0, proof.size());
        assertTrue(MerkleTreePrimitives.verifySubtreeInclusionProof(
            0, 0, 1, leaves.get(0), root, proof, hash));
        assertTrue("the root of a one-leaf tree is its leaf hash",
            Arrays.areEqual(root, leaves.get(0)));
    }

    /**
     * A proof with one flipped bit must not verify. This is the assertion that would still pass if
     * verify() ignored the proof entirely, so it is the one worth having.
     */
    @Test
    public void testTamperedProofIsRejected()
        throws Exception
    {
        MerkleTreeHash hash = hash();
        List<byte[]> leaves = leafHashes(8, hash);
        byte[] root = new ListMerkleTreeNodeSource(leaves, hash).getFullSubtreeHash(0, 8);

        List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(3, 0, 8, leaves, hash);

        // Pinned so the loop below cannot silently iterate zero times: an 8-leaf tree is 3 levels
        // deep, so an inclusion proof is exactly 3 sibling hashes.
        assertEquals(3, proof.size());

        assertTrue("control: the untampered proof verifies",
            MerkleTreePrimitives.verifySubtreeInclusionProof(3, 0, 8, leaves.get(3), root, proof, hash));

        for (int i = 0; i != proof.size(); i++)
        {
            List<byte[]> tampered = new ArrayList<byte[]>(proof);
            byte[] sibling = Arrays.clone(tampered.get(i));
            sibling[0] ^= 0x01;
            tampered.set(i, sibling);

            assertFalse("a flipped bit in sibling " + i + " must not verify",
                MerkleTreePrimitives.verifySubtreeInclusionProof(3, 0, 8, leaves.get(3), root, tampered, hash));
        }
    }

    /**
     * A valid proof for one leaf must not verify a different leaf, at either index.
     */
    @Test
    public void testProofDoesNotTransferToAnotherLeaf()
        throws Exception
    {
        MerkleTreeHash hash = hash();
        List<byte[]> leaves = leafHashes(8, hash);
        byte[] root = new ListMerkleTreeNodeSource(leaves, hash).getFullSubtreeHash(0, 8);

        List<byte[]> proofFor3 = MerkleTreePrimitives.generateSubtreeInclusionProof(3, 0, 8, leaves, hash);

        assertFalse("leaf 5's hash must not verify under leaf 3's proof",
            MerkleTreePrimitives.verifySubtreeInclusionProof(3, 0, 8, leaves.get(5), root, proofFor3, hash));
        assertFalse("leaf 3's proof must not verify at index 5",
            MerkleTreePrimitives.verifySubtreeInclusionProof(5, 0, 8, leaves.get(3), root, proofFor3, hash));
    }

    private static void assertEveryLeafProves(int n)
        throws Exception
    {
        MerkleTreeHash hash = hash();
        List<byte[]> leaves = leafHashes(n, hash);
        byte[] root = new ListMerkleTreeNodeSource(leaves, hash).getFullSubtreeHash(0, n);

        assertEquals(hash.getHashSize(), root.length);

        for (int i = 0; i != n; i++)
        {
            List<byte[]> proof = MerkleTreePrimitives.generateSubtreeInclusionProof(i, 0, n, leaves, hash);

            assertTrue("leaf " + i + " of " + n + " must prove against the root",
                MerkleTreePrimitives.verifySubtreeInclusionProof(i, 0, n, leaves.get(i), root, proof, hash));
        }
    }
}
