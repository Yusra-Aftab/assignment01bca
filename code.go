package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Block represents a block in a blockchain.
type Block struct {
	Transaction  string
	Nonce        int
	PreviousHash string
	Hash         string
}

// CreateHash generates the hash for a block.
func CreateHash(b Block) string {
	data := fmt.Sprintf("%s%d%s", b.Transaction, b.Nonce, b.PreviousHash)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// CalculateHash calculates the SHA-256 hash of a given string.
func CalculateHash(stringToHash string) string {
	hash := sha256.Sum256([]byte(stringToHash))
	return hex.EncodeToString(hash[:])
}

// NewBlock creates a new block with the given transaction, nonce, and previous hash.
func NewBlock(transaction string, nonce int, previousHash string) *Block {
	block := Block{
		Transaction:  transaction,
		Nonce:        nonce,
		PreviousHash: previousHash,
	}
	block.Hash = CreateHash(block)
	return &block
}

// ChangeBlock modifies the transaction of a given block.
func ChangeBlock(block *Block, newTransaction string) {
	block.Transaction = newTransaction
	block.Hash = CreateHash(*block)
}

// VerifyChain checks the integrity of the blockchain.
func VerifyChain(blocks []*Block) bool {
	for i := 1; i < len(blocks); i++ {
		currentBlock := blocks[i]
		previousBlock := blocks[i-1]

		// Verify that the current block's PreviousHash matches the hash of the previous block.
		if currentBlock.PreviousHash != CreateHash(*previousBlock) {
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
		fmt.Printf("Transaction: %s\n", block.Transaction)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Previous Hash: %s\n", block.PreviousHash)
		fmt.Printf("Block Hash: %s\n", block.Hash)
		fmt.Println()
		fmt.Println("--------------------------------------------------------")
	}
}

func main() {
	// Create some example blocks.
	block1 := NewBlock("Alice to Bob", 12345, "genesis_block_hash")
	block2 := NewBlock("Bob to Carol", 67890, block1.Hash)
	block3 := NewBlock("Carol to Dave", 98765, block2.Hash)

	// Create a slice to hold the blocks.
	blocks := []*Block{block1, block2, block3}

	// Display the blocks in a nice format.
	fmt.Println()
	fmt.Println("BlockChain Before Changes .....")
	DisplayBlocks(blocks)

	// Change the transaction of block2.
	newTransaction := "Mallory to Eve"
	ChangeBlock(block2, newTransaction)

	// Display the blocks after changing block2's transaction.

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
	block3Hash := CalculateHash(fmt.Sprintf("%s%d%s", block3.Transaction, block3.Nonce, block3.PreviousHash))

	fmt.Println()
	// Display the hash of block3.
	fmt.Printf("Hash of block3: %s\n", block3Hash)
}
