package storage

import (
	"github.com/dgraph-io/badger/v4"
	"log"
)

func OpenRepository() Repository {
	opt := badger.DefaultOptions("data/badger")
	opt.ValueLogFileSize = (64 << 20) - 1
	opt.MemTableSize = 32 << 20
	db, err := badger.Open(opt)
	if err != nil {
		log.Fatal(err)
	}
	return Repository{db}
}

func OpenInMemoryRepository() Repository {
	opt := badger.DefaultOptions("").WithInMemory(true)
	opt.ValueLogFileSize = (64 << 20) - 1
	opt.MemTableSize = 32 << 20
	db, err := badger.Open(opt)
	if err != nil {
		log.Fatal(err)
	}
	return Repository{db}
}
