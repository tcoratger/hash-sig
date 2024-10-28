use super::{sha::Sha256Hash, OneWay, VectorCommitment};

const DEPTH: usize = 2;
const WIDTH: usize = 1 << DEPTH; // lifetime is 2^DEPTH keys

/// Hash-Tree based on a OWF
pub struct HashTree<H: OneWay> {
    _marker_h: std::marker::PhantomData<H>,
}

/// Opening in a hash-tree
pub struct HashTreeOpening<H: OneWay> {
    /// The leaf to be opened
    leaf: H::Domain,
    /// The co-path needed to verify
    /// It has size DEPTH
    co_path: [H::Domain; DEPTH],
}

impl<H: OneWay> VectorCommitment for HashTree<H> {
    type Domain = H::Domain;
    type Commitment = H::Domain;
    type Opening = HashTreeOpening<H>;

    fn commit(vector: &[Self::Domain]) -> Self::Commitment {
        assert!(
            vector.len() == WIDTH,
            "Hash-Tree commit: Vector should have correct length"
        );

        // We compute the tree layer by layer.
        // In every step, we reuse the first half
        // of the previous layer for the next layer.
        //
        // Example for DEPTH = 2.
        // -> a b c d
        // -> H(a,b) H(c,d) c d
        // -> H(H(a,b),H(c,d)) H(c,d) c d
        let mut layer = vector.to_owned();
        let mut layer_size = WIDTH;
        for _ in 0..DEPTH {
            layer_size = layer_size / 2;
            for i in 0..layer_size {
                // hash / compress element 2 * i and 2 * i + 1
                // and place it into the i-th position of layer
                let left = 2 * i;
                let right = 2 * i + 1;
                let parent = H::apply(&layer[left..=right]);
                layer[i] = parent;
            }
        }

        // now the root is in the very first position
        *layer.first().unwrap()
    }

    fn open(vector: &[Self::Domain], position: u64) -> Self::Opening {
        assert!(
            position < WIDTH as u64,
            "Hash-Tree open: Position should be within bounds."
        );
        // NOTE: This will be very slow if we do not store the inner nodes of the tree after commit

        // Re-compute the tree layer by layer.
        // whenever a layer is finished, we put
        // the sibling node in the co-path.
        let mut co_path = [H::Domain::default(); DEPTH];
        let mut layer = vector.to_owned();
        let mut layer_size = WIDTH;
        let mut current_position = position;
        for l in 0..DEPTH {
            // put sibling of our node in the co-path
            let sibling_position = current_position ^ 0x01;
            co_path[l] = layer[sibling_position as usize];
            // we build the new layer
            layer_size = layer_size / 2;
            for i in 0..layer_size {
                let left = 2 * i;
                let right = 2 * i + 1;
                let parent = H::apply(&layer[left..=right]);
                layer[i] = parent;
            }
            // new position in new layer
            current_position = current_position >> 1;
        }

        // Put the leaf in the opening and return it
        let leaf = vector[position as usize];

        HashTreeOpening { leaf, co_path }
    }

    fn verify(com: &Self::Commitment, position: u64, opening: &Self::Opening) -> bool {
        assert!(
            position < WIDTH as u64,
            "Hash-Tree verify: Position should be within bounds."
        );

        // We recompute the Merkle root using the co-path.
        // For that, iteratively compute all nodes on the leaf-to-root path.
        // We also need to keep track of their position within their layer.
        let mut current_node = opening.leaf.clone();
        let mut current_position = position;
        for layer in 0..DEPTH {
            // Need to distinguish two cases, depending on
            // if current is a left child or a right child
            let children = if current_position % 2 == 0 {
                // left child, so co-path contains the right sibling
                [current_node, opening.co_path[layer]]
            } else {
                // right child, so co-path contains the left sibling
                [opening.co_path[layer], current_node]
            };
            // now hash and determine new position
            current_node = H::apply(&children);
            current_position = current_position >> 1;
        }

        // Now current should be the Merkle root
        current_node == *com
    }
}

/// SHA256-based Hash-Tree
pub type Sha256HashTree = HashTree<Sha256Hash>;

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::symmetric::OneWay;

    use super::*;

    #[test]
    fn test_commit_open_verify() {
        let mut rng = thread_rng();

        // We test that committing, opening, and verifying works as expected

        // First, get a vector
        let vector: [<Sha256Hash as OneWay>::Domain; WIDTH] =
            std::array::from_fn(|_| <Sha256Hash as OneWay>::sample(&mut rng));

        // now compute a commitment
        let com = Sha256HashTree::commit(&vector);

        // now check that opening and verification works as expected
        for position in 0..WIDTH {
            let opening = Sha256HashTree::open(&vector, position as u64);
            assert!(Sha256HashTree::verify(&com, position as u64, &opening));
        }
    }
}
