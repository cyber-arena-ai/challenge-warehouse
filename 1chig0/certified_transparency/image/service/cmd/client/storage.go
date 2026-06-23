package main

import (
	"certified-transparency/pkg/models"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

const DATA_DIR = "data-client"

func saveSot(sot models.SignedOwnershipTimestamp) error {
	err := os.MkdirAll(filepath.Join(DATA_DIR, "sot"), 0700)
	if err != nil {
		return err
	}

	fname := filepath.Join(DATA_DIR, "sot", fmt.Sprintf("%d.sot", time.Now().UnixMilli()))
	err = os.WriteFile(fname, sot.Serialize(), 0600)
	if err == nil {
		log.Printf("wrote your private ownership proof (SOT) to %q\n", fname)
	}
	return err
}

func saveProof(proof models.TreeLeafProof) error {
	err := os.MkdirAll(filepath.Join(DATA_DIR, "proof"), 0700)
	if err != nil {
		return err
	}

	fname := filepath.Join(DATA_DIR, "proof", fmt.Sprintf("%d_%d.proof", proof.Index, time.Now().UnixMilli()))
	err = os.WriteFile(fname, proof.Serialize(), 0600)
	if err == nil {
		log.Printf("wrote your ownership proof to %q\n", fname)
	}
	return err
}

func readSot(f *os.File) models.SignedOwnershipTimestamp {
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	sot, err := models.UnserializeSignedOwnershipTimestamp(data)
	if err != nil {
		log.Fatal(err)
	}
	return sot
}

func readProof(f *os.File) models.TreeLeafProof {
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	proof, err := models.UnserializeTreeLeafProof(data)
	if err != nil {
		log.Fatal(err)
	}
	return proof
}

func listFiles(subfolder string) ([]string, error) {
	var result []string
	err := filepath.WalkDir(filepath.Join(DATA_DIR, subfolder), func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == "."+subfolder {
			result = append(result, filepath.Join(DATA_DIR, subfolder, d.Name()))
		}
		return nil
	})
	return result, err
}
