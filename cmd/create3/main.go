package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const THREAD_COUNT = 16

var (
	Create3FactoryAddress = "0x9fBB3DF7C40Da2e5A0dE984fFE2CCB7C47cd0ABf"
	Create3InitCodeHash   = common.FromHex("0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f")
)

func calculateAddressBySalt(deployerAddress string, factoryAddress string, salt string) string {
	saltWithDeployer := crypto.Keccak256Hash(common.FromHex(deployerAddress), common.FromHex(salt))
	create2Hash := crypto.Keccak256Hash([]byte{0xff}, common.FromHex(factoryAddress), saltWithDeployer.Bytes(), Create3InitCodeHash)
	proxyAddress := create2Hash.Bytes()
	proxyAddress = proxyAddress[len(proxyAddress)-20:]

	createHash := crypto.Keccak256Hash([]byte{0xd6, 0x94}, proxyAddress, []byte{0x01})
	deploymentAddress := createHash.Hex()[len(createHash.Hex())-40:]

	address := common.HexToAddress("0x" + deploymentAddress)

	return address.String()
}

func scanSaltAgent(ctx context.Context, deployerAddress string, leading string, factoryAddress string, ch chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	address := ""
	salt := ""

	leadingTemplate := leading[:len(leading)-1]

	for i := 0; i < 100000; i++ {
		saltBytes := make([]byte, 12)
		rand.Read(saltBytes)
		saltHex := hex.EncodeToString(saltBytes)
		salt = "0x0000000000000000000000000000000000000000" + saltHex
		address = calculateAddressBySalt(deployerAddress, factoryAddress, salt)
		if strings.HasPrefix(address, "0x"+leadingTemplate) {
			fmt.Println(salt, address)
		}
		if strings.HasPrefix(address, "0x"+leading) {
			select {
			case <-ctx.Done():
				return

			default:
				ch <- (salt + ";" + address)
				return
			}
		}
	}
}

func scanSalt(deployerAddress string, leading string, factoryAddress string) (string, string) {
	for {
		wg := sync.WaitGroup{}
		messageCh := make(chan string)
		notFoundCh := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())

		wg.Add(THREAD_COUNT)

		go func() {
			// Scan with 16 threads
			for i := 0; i < THREAD_COUNT; i++ {
				go scanSaltAgent(ctx, deployerAddress, leading, factoryAddress, messageCh, &wg)
			}

			wg.Wait()
			notFoundCh <- "notfound"
		}()

		select {
		case <-notFoundCh:
			cancel()
			continue
		case data := <-messageCh:
			parts := strings.Split(data, ";")
			cancel()
			return parts[0], parts[1]
		}
	}
}

func main() {
	deployerAddress := os.Args[1]
	leading := os.Args[2]
	factoryAddress := Create3FactoryAddress

	if len(os.Args) > 3 {
		factoryAddress = os.Args[3]
	}

	salt, address := scanSalt(deployerAddress, leading, factoryAddress)

	println("\n===============================\n")
	print(salt, " ", address)
}
