package tako_gnark_ecdsa

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
)

// ComputeEthereumAddress 计算以太坊地址
func ComputeEthereumAddress(pubKey *ecdsa.PublicKey) []byte {
	// 1️⃣ 获取 64 字节未压缩公钥（去掉 0x04 前缀）
	pubKeyBytes := pubKey.Bytes() // `gnark-crypto` 提供的方法
	pubKeyBytes = pubKeyBytes[:]  // 去掉 `0x04` 前缀

	// 2️⃣ 计算 Keccak256 哈希
	hash := sha3.NewLegacyKeccak256()
	log.Printf("ComputeEthereumAddress pubKeyBytes %x", pubKeyBytes)
	hash.Write(pubKeyBytes)
	hashed := hash.Sum(nil)
	log.Printf("ComputeEthereumAddress hashed %x", hashed)

	address := hashed[12:]
	log.Printf("ComputeEthereumAddress address %x", address)

	return address
}

func privateKeyToHex(priv *ecdsa.PrivateKey) string {
	// priv.D 是一个 *big.Int 类型，表示私钥的数值
	// 将其转换为16进制字符串，移除 "0x" 前缀
	hexStr := priv.Bytes()[64:]
	// 确保输出的长度是固定的（通常是64个字符，补0）

	addr := fmt.Sprintf("%x", hexStr)
	return addr
}

// **从公钥计算以太坊地址**
func isValidEthereumPrivateKey(hexKey string) bool {
	// 1️⃣ **检查长度**
	if len(hexKey) != 64 {
		return false
	}

	// 2️⃣ **转换 Hex -> BigInt**
	privBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return false
	}
	privKey := new(big.Int).SetBytes(privBytes)

	// 3️⃣ **检查范围**
	n := secp256k1.S256().N // secp256k1 的阶
	if privKey.Cmp(big.NewInt(1)) < 0 || privKey.Cmp(n) >= 0 {
		return false
	}

	return true
}
