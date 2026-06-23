package main

import (
	"bytes"
	"certified-transparency/pkg"
	"certified-transparency/pkg/models"
	"certified-transparency/pkg/requests"
	"certified-transparency/pkg/storage"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/alecthomas/kingpin/v2"
	"io"
	"log"
	"os"
	"strings"
)

func hashFile(f *os.File) models.Hash {
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	return models.ToHash(h.Sum(nil))
}

func CmdShow(url string) error {
	api := requests.NewLogApiClient("http://" + url + ":3000")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}
	sth, err := api.GetSth()
	if err != nil {
		return err
	}

	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}
	if !pkg.VerifyTreeHead(pubkey, &sth) {
		return errors.New("invalid sth signature")
	}

	log.Printf("CT Log Server:     http://%s:3000\n", url)
	log.Printf("CT Monitor Server: http://%s:3001\n", url)
	log.Printf("Public Key:       %s\n", hex.EncodeToString(pubkey))
	log.Printf("Log Size:         %d\n", sth.Size)
	log.Printf("Timestamp:        %s\n", sth.Timestamp.String())
	log.Printf("Head Hash:        %s\n", hex.EncodeToString(sth.Hash[:]))

	return nil
}

func CmdPreregister(url string, file *os.File, name string) error {
	api := requests.NewLogApiClient("http://" + url + ":3000")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}

	contentHash := hashFile(file)
	log.Printf("submitting %s for name %q in private...\n", hex.EncodeToString(contentHash[:]), name)
	sot, err := api.SignEntry(models.Ownership{
		ContentHash: contentHash,
		Name:        name,
	})
	if err != nil {
		return err
	}
	if !pkg.VerifyOwnership(pubkey, &sot) {
		return errors.New("invalid sot signature")
	}
	if !bytes.Equal(sot.Ownership.ContentHash[:], contentHash[:]) {
		log.Printf("%v\n", hex.EncodeToString(sot.Ownership.ContentHash[:]))
		log.Printf("%v\n", hex.EncodeToString(contentHash[:]))
		return errors.New("sot for wrong hash")
	}

	return saveSot(sot)
}

func CmdRegister(url string, file *os.File, name string, dataPrivate string, dataPublic string) error {
	api := requests.NewLogApiClient("http://" + url + ":3000")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}

	contentHash := hashFile(file)
	clientPubkey, _ := storage.LoadClientSignKeys()
	log.Printf("recording ownership of %s for name %q to log...\n", hex.EncodeToString(contentHash[:]), name)
	index, err := api.AddEntry(requests.AddEntryRequest{
		ContentHash:          contentHash[:],
		Name:                 name,
		PubKey:               clientPubkey,
		DataForPrivateClaims: dataPrivate,
		DataForPublicClaims:  dataPublic,
	})
	if err != nil {
		return err
	}
	log.Printf("log position: %d\n", index)

	proof, err := api.GetEntryAndProof(index)
	if err != nil {
		return err
	}
	if !pkg.VerifyTreeHead(pubkey, &proof.Head) {
		return errors.New("invalid sth signature in proof")
	}
	if !storage.VerifyLeafProofHashes(proof) {
		return errors.New("invalid proof hash chain")
	}
	if !bytes.Equal(proof.Leaf.Ownership.ContentHash[:], contentHash[:]) {
		return errors.New("proof for wrong hash")
	}

	return saveProof(proof)
}

func CmdVerify(url string, file *os.File) error {
	api := requests.NewLogApiClient("http://" + url + ":3000")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}

	if strings.HasSuffix(file.Name(), ".sot") {
		sot := readSot(file)
		log.Printf("Time: %s\n", sot.Timestamp.String())
		log.Printf("Name: %q\n", sot.Ownership.Name)
		log.Printf("Hash: %s\n", hex.EncodeToString(sot.Ownership.ContentHash[:]))
		if !pkg.VerifyOwnership(pubkey, &sot) {
			return errors.New("invalid sot signature")
		}
		return nil

	} else if strings.HasSuffix(file.Name(), ".proof") {
		proof := readProof(file)
		log.Printf("Created: %s\n", proof.Leaf.Created.String())
		log.Printf("Name:    %q\n", proof.Leaf.Ownership.Name)
		log.Printf("Hash:    %s\n", hex.EncodeToString(proof.Leaf.Ownership.ContentHash[:]))
		log.Printf("Index:   %d\n", proof.Index)
		if !pkg.VerifyTreeHead(pubkey, &proof.Head) {
			return errors.New("invalid sth signature")
		}
		if !storage.VerifyLeafProofHashes(proof) {
			return errors.New("invalid proof hash chain")
		}
		return nil

	} else {
		return errors.New("invalid filename")
	}
}

func CmdClaim(url string, file *os.File, index uint64) error {
	api := requests.NewLogApiClient("http://" + url + ":3000")
	api2 := requests.NewMonitorApiClient("http://" + url + ":3001")
	pubkey, err := api.GetPubkey()
	if err != nil {
		return err
	}
	if len(pubkey) != ed25519.PublicKeySize {
		return errors.New("invalid public key")
	}

	claimedProof, err := api.GetEntryAndProof(index)
	if err != nil {
		return err
	}

	var result requests.ClaimResponse

	if strings.HasSuffix(file.Name(), ".sot") {
		sot := readSot(file)
		if !pkg.VerifyOwnership(pubkey, &sot) {
			return errors.New("invalid sot signature")
		}

		result, err = api2.ClaimPrivate(sot, claimedProof)
		if err != nil {
			return err
		}

	} else if strings.HasSuffix(file.Name(), ".proof") {
		proof := readProof(file)
		_, clientPrivateKey := storage.LoadClientSignKeys()
		if !pkg.VerifyTreeHead(pubkey, &proof.Head) {
			return errors.New("invalid sth signature")
		}
		if !storage.VerifyLeafProofHashes(proof) {
			return errors.New("invalid proof hash chain")
		}

		result, err = api2.ClaimPublic(proof, claimedProof, pkg.SignLeaf(clientPrivateKey, &proof.Leaf))
		if err != nil {
			return err
		}

	} else {
		return errors.New("invalid filename")
	}

	log.Printf("Granted: %v\n", result.Granted)
	log.Printf("Data:    %q\n", result.Data)

	return nil
}

func main() {
	server := kingpin.Flag("server", "server base URL").Envar("SERVER").Default("127.0.0.1").String()

	showCommand := kingpin.Command("show", "show certified transparency log server information")

	preregisterCommand := kingpin.Command("preregister", "Pre-Register a file")
	preregisterName := preregisterCommand.Flag("name", "Your name").Default("anonymous").String()
	preregisterFile := preregisterCommand.Arg("file", "filename").Required().File()

	registerCommand := kingpin.Command("register", "Register a file")
	registerName := registerCommand.Flag("name", "Your name").Default("anonymous").String()
	registerDataPrivate := registerCommand.Flag("data-private", "Contact information for private claims against this ownership").Default("").String()
	registerDataPublic := registerCommand.Flag("data-public", "Contact information for public claims against this ownership").Default("").String()
	registerFile := registerCommand.Arg("file", "filename").Required().File()

	verifyCommand := kingpin.Command("verify", "Verify a file")
	verifyFile := verifyCommand.Arg("file", "filename").Required().File()

	monitorCommand := kingpin.Command("monitor", "Watch the log for violations")

	claimCommand := kingpin.Command("claim", "Claim a violation")
	claimFile := claimCommand.Arg("file", "saved claim filename").Required().File()
	claimIndex := claimCommand.Arg("index", "index of violating log entry").Required().Uint64()

	var err error
	switch kingpin.Parse() {
	case showCommand.FullCommand():
		err = CmdShow(*server)
	case preregisterCommand.FullCommand():
		err = CmdPreregister(*server, *preregisterFile, *preregisterName)
	case registerCommand.FullCommand():
		err = CmdRegister(*server, *registerFile, *registerName, *registerDataPrivate, *registerDataPublic)
	case verifyCommand.FullCommand():
		err = CmdVerify(*server, *verifyFile)
	case monitorCommand.FullCommand():
		err = CmdMonitor(*server)
	case claimCommand.FullCommand():
		err = CmdClaim(*server, *claimFile, *claimIndex)
	}
	if err != nil {
		log.Fatal(err)
	}
}
