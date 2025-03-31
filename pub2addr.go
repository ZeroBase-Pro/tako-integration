package tako_gnark_ecdsa

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/constraint/solver"
)

// Pub2AddrHint calculates Ethereum address from public key coordinates
func Pub2AddrHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	// Expecting 8 inputs: 4 for X coordinate and 4 for Y coordinate
	if len(inputs) != 8 {
		return fmt.Errorf("expected 8 inputs, got %d", len(inputs))
	}

	// Reconstruct X coordinate from 4 parts
	//
	//for i := 0; i < len(inputs); i++ {
	//	log.Printf("inputs[%d] %x", i, inputs[i])
	//}

	var x fp.Element
	x.SetBigInt(inputs[0])
	for i := 1; i < 4; i++ {
		var z fp.Element
		limbs := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
		z.SetBigInt(limbs)

		var a fp.Element
		a.SetBigInt(inputs[i])
		x.Mul(&x, &z).Add(&x, &a)
	}

	// Reconstruct Y coordinate from 4 parts
	var y fp.Element
	y.SetBigInt(inputs[4])
	for i := 5; i < 8; i++ {
		var z fp.Element
		limbs := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
		z.SetBigInt(limbs)

		var a fp.Element
		a.SetBigInt(inputs[i])
		y.Mul(&y, &z).Add(&y, &a)
	}

	// Create public key
	pubKey := ecdsa.PublicKey{
		A: secp256k1.G1Affine{
			X: x,
			Y: y,
		},
	}
	addrBy := ComputeEthereumAddress(&pubKey)
	log.Printf("address %x", addrBy)

	// Convert to uncompressed public key bytes (65 bytes: 0x04 || X || Y)
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(pubBytes[1:33], xBytes[:])
	copy(pubBytes[33:], yBytes[:])

	// // Calculate Keccak-256 hash
	// hash := sha3.NewLegacyKeccak256()

	// log.Printf("Pub2AddrHint pubBytes %x", pubBytes[1:])
	// hash.Write(pubBytes[1:]) // Skip the 0x04 prefix
	// hashSum := hash.Sum(nil)

	// // Take last 20 bytes and convert to big.Int
	// addressBytes := hashSum[12:]

	// // Last 20 bytes
	// log.Printf("Pub2AddrHint addressBytes %x", addressBytes)
	// addr := new(big.Int).SetBytes(addressBytes)
	// log.Printf("Pub2AddrHint addr %d", addr)

	// Set output
	for i := 0; i < 64; i++ {
		outputs[i] = big.NewInt(int64(pubBytes[i+1]))
	}

	return nil
}

// func PrintHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
// 	log.Printf("PrintHint inputs %v", inputs)
// 	log.Printf("PrintHint outputs %v", outputs)
// 	return nil
// }

// 注册 Hint
func init() {
	solver.RegisterHint(Pub2AddrHint)
	// solver.RegisterHint(PrintHint)
}
