package tako_gnark_ecdsa

import (
	"fmt"
	"github.com/consensys/gnark/frontend"

	poseidonbn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash"
	poseidon2_permutation "github.com/consensys/gnark/std/permutation/poseidon2"
)

func MerkleTreeVerify(api frontend.API, rootHash frontend.Variable, merklePath []frontend.Variable, proofIndex frontend.Variable) error {
	hsh, err := NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}
	var M merkle.MerkleProof
	M.RootHash = rootHash
	M.Path = merklePath
	M.VerifyProof(api, hsh, proofIndex)
	return nil
}

// NewMerkleDamgardHasher returns a Poseidon2 hasher using the Merkle-Damgard
// construction with the default parameters.
func NewMerkleDamgardHasher(api frontend.API) (hash.FieldHasher, error) {
	f, err := NewPoseidon2(api)
	if err != nil {
		return nil, fmt.Errorf("could not create poseidon2 hasher: %w", err)
	}
	return hash.NewMerkleDamgardHasher(api, f, make([]byte, 32)), nil
}

// NewPoseidon2 returns a new Poseidon2 hasher with default parameters as
// defined in the gnark-crypto library.
func NewPoseidon2(api frontend.API) (*poseidon2_permutation.Permutation, error) {
	params := poseidonbn254.NewParameters(2, 6, 50)
	return poseidon2_permutation.NewPoseidon2FromParameters(api, params.Width, params.NbFullRounds, params.NbPartialRounds)
}
