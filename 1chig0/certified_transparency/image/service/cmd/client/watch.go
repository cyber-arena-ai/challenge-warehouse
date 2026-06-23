package main

import (
	"certified-transparency/pkg/models"
	"certified-transparency/pkg/requests"
	"crypto/ed25519"
	"errors"
	"log"
	"os"
)

type OwnedHash struct {
	ownership models.Ownership
	file      string
}

func readAllOwnedHashes() map[models.Hash][]OwnedHash {
	hashes := make(map[models.Hash][]OwnedHash)

	files, err := listFiles("sot")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		sot, err := models.UnserializeSignedOwnershipTimestamp(data)
		if err != nil {
			log.Fatal(err)
		}
		if lst, ok := hashes[sot.Ownership.ContentHash]; ok {
			hashes[sot.Ownership.ContentHash] = append(lst, OwnedHash{
				ownership: sot.Ownership,
				file:      file,
			})
		} else {
			hashes[sot.Ownership.ContentHash] = []OwnedHash{{
				ownership: sot.Ownership,
				file:      file,
			}}
		}
	}

	files, err = listFiles("proof")
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		proof, err := models.UnserializeTreeLeafProof(data)
		if err != nil {
			log.Fatal(err)
		}
		if lst, ok := hashes[proof.Leaf.Ownership.ContentHash]; ok {
			hashes[proof.Leaf.Ownership.ContentHash] = append(lst, OwnedHash{
				ownership: proof.Leaf.Ownership,
				file:      file,
			})
		} else {
			hashes[proof.Leaf.Ownership.ContentHash] = []OwnedHash{{
				ownership: proof.Leaf.Ownership,
				file:      file,
			}}
		}
	}

	return hashes
}

func checkLeafForViolations(data requests.NewLeafMessage, hashes map[models.Hash][]OwnedHash) {
	leaf, err := models.UnserializeTreeLeaf(data.Leaf)
	if err != nil {
		log.Fatal("Invalid leaf!", err)
	}
	if violations, ok := hashes[leaf.Ownership.ContentHash]; ok && len(violations) > 0 {
		log.Printf("New entry #%d by %q violates %d of your ownerships:\n", data.Index, leaf.Ownership.Name, len(violations))
		for _, v := range violations {
			log.Printf("- %q\n", v.file)
		}
	}
}

func CmdMonitor(url string) error {
	api := requests.NewMonitorApiClient("http://" + url + ":3001")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}

	myHashes := readAllOwnedHashes()
	log.Printf("watching for %d file hashes...\n", len(myHashes))
	leaves := make(chan requests.NewLeafMessage, 32)
	go func() {
		err := api.Monitor(leaves)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()

	for {
		leaf := <-leaves
		checkLeafForViolations(leaf, myHashes)
	}

	return nil
}
