package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Block struct {
	Trans    string
	Nonce    int
	PrevHash string
	Hash     string
}

// Generates the hash for a block.
func CreateHash(blo Block) string {
	data := fmt.Sprintf("%s%d%s", blo.Trans, blo.Nonce, blo.PrevHash)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Calculates the SHA-256 hash.
func CalculateHash(strtohash string) string {
	hash := sha256.Sum256([]byte(strtohash))
	return hex.EncodeToString(hash[:])
}

// Creates a new block.
func AddBlock(trans string, nonce int, prevHash string) *Block {
	block := Block{
		Trans:    trans,
		Nonce:    nonce,
		PrevHash: prevHash,
	}
	block.Hash = CreateHash(block)
	return &block
}

// Modifies the Transaction of a given block.
func EditBlock(block *Block, newTrans string) {
	block.Trans = newTrans
	block.Hash = CreateHash(*block)
}

// VerifyChain checks the integrity of the blockchain.
func VerifyChain(blocks []*Block) bool {
	for i := 1; i < len(blocks); i++ {
		currentBlock := blocks[i]
		previousBlock := blocks[i-1]

		// Verify that the current block's PrevHash matches the hash of the previous block.
		if currentBlock.PrevHash != CreateHash(*previousBlock) {
			return false
		}

		// Verify that the current block's hash is correctly computed.
		if currentBlock.Hash != CreateHash(*currentBlock) {
			return false
		}
	}

	return true
}

// DisplayBlocks prints all the blocks in a nice format.
func DisplayBlocks(blocks []*Block) {
	fmt.Println("Blockchain:")
	fmt.Println("--------------------------------------------------------")

	for _, block := range blocks {
		fmt.Printf("Trans: %s\n", block.Trans)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Previous Hash: %s\n", block.PrevHash)
		fmt.Printf("Block Hash: %s\n", block.Hash)
		fmt.Println()
		fmt.Println("--------------------------------------------------------")
	}
}

func main() {
	// Create some example blocks.
	block1 := AddBlock("Uzair to Yusra", 32345, "genesis_block_hash")
	block2 := AddBlock("Yusra to Arnish", 87190, block1.Hash)
	block3 := AddBlock("Umoo to Umoo", 23445, block2.Hash)

	// Create a slice to hold the blocks.
	blocks := []*Block{block1, block2, block3}

	// Display the blocks in a nice format.
	fmt.Println()
	fmt.Println("BlockChain Before Changes .....")
	DisplayBlocks(blocks)

	// Change the Trans of block2.
	newTrans := "Mallory to Eve"
	EditBlock(block2, newTrans)

	// Display the blocks after changing block2's Trans.

	fmt.Println()
	fmt.Println("BlockChain After Changes .....")
	DisplayBlocks(blocks)

	fmt.Println("\nValidity Check .....")
	// Verify the blockchain.
	isValid := VerifyChain(blocks)
	if isValid {
		fmt.Println("Blockchain is valid.")
	} else {
		fmt.Println("Blockchain is NOT valid. Changes detected!")
	}

	// Calculate the hash of block3.
	block3Hash := CalculateHash(fmt.Sprintf("%s%d%s", block3.Trans, block3.Nonce, block3.PrevHash))

	fmt.Println()
	// Display the hash of block3.
	fmt.Printf("Hash of block3: %s\n", block3Hash)
}
