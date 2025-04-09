package tako_gnark_ecdsa

import (
	"fmt"
	"log"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/evmprecompiles"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints" // 用于处理字节数组
)

type MaskCircuit struct {
	// Address Data
	Message  emulated.Element[emulated.Secp256k1Fr]
	V        frontend.Variable
	R        emulated.Element[emulated.Secp256k1Fr]
	S        emulated.Element[emulated.Secp256k1Fr]
	Expected sw_emulated.AffinePoint[emulated.Secp256k1Fp]
	Address  frontend.Variable
	RootHash frontend.Variable
	Index    frontend.Variable
	Path     [14]frontend.Variable
}

func (circuit *MaskCircuit) Define(api frontend.API) error {

	res := evmprecompiles.ECRecover(api, circuit.Message, circuit.V, circuit.R, circuit.S, 0, 0)

	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	curve.AssertIsEqual(&circuit.Expected, res)

	pubBytes_noPrefix, err := api.Compiler().NewHint(Pub2AddrHint, 64,
		res.X.Limbs[3], res.X.Limbs[2], res.X.Limbs[1], res.X.Limbs[0],
		res.Y.Limbs[3], res.Y.Limbs[2], res.Y.Limbs[1], res.Y.Limbs[0])
	if err != nil {
		return fmt.Errorf("Pub2AddrHint hint: %w", err)
	}
	var hash_in [64]uints.U8
	for i := 0; i < 64; i++ {
		hash_in[i].Val = pubBytes_noPrefix[i] // 假设这里把 uint8 -> uints.U8
	}
	pubBytes_hash, err := Keccak256(api, hash_in)

	addressBytes := make([]frontend.Variable, 20)
	for i := 0; i < 20; i++ {
		addressBytes[i] = pubBytes_hash[i+12].Val
	}
	addr_fv := BigEndianBytesToVar(api, addressBytes)
	merklePath := make([]frontend.Variable, 14)
	merklePath[0] = addr_fv
	for i := 1; i < len(merklePath); i++ {
		merklePath[i] = circuit.Path[i]
	}

	err = MerkleTreeVerify(api, circuit.RootHash, merklePath, circuit.Index)
	if err != nil {
		log.Printf("MerkleTreeVerify %s", err)
	}
	return nil
}
