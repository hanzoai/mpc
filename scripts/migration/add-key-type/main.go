package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/luxfi/zapdb"

	"github.com/hanzoai/mpc/pkg/kvstore"
	"github.com/hanzoai/mpc/pkg/logger"
)

func main() {
	logger.Init("production", false)
	nodeName := flag.String("name", "", "Provide node name")
	flag.Parse()
	if *nodeName == "" {
		logger.Fatal("Node name is required", nil)
	}

	dbPath := fmt.Sprintf("./db/%s", *nodeName)

	// Create BadgerConfig struct
	config := kvstore.BadgerConfig{
		NodeID:              *nodeName,
		EncryptionKey:       []byte(""), // Empty key for migration
		BackupEncryptionKey: []byte(""), // Empty key for migration
		BackupDir:           "./backups",
		DBPath:              dbPath,
	}

	badgerKv, err := kvstore.NewBadgerKVStore(config)
	if err != nil {
		logger.Fatal("Failed to create badger kv store", err)
	}

	if err := badgerKv.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			var result []byte

			if err := item.Value(func(val []byte) error {
				result = append(result, val...)
				return nil
			}); err != nil {
				return err
			}

			if !strings.HasPrefix(string(key), "eddsa:") {
				if !strings.HasPrefix(string(key), "ecdsa:") {
					if err := badgerKv.DB.Update(func(txn *badger.Txn) error {
						if err := txn.Set([]byte(fmt.Sprintf("ecdsa:%s", key)), result); err != nil {
							return err
						}
						return txn.Delete(key)
					}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}); err != nil {
		logger.Fatal("Failed to migrate keys", err)
	}

	keys, err := badgerKv.Keys()
	if err != nil {
		logger.Fatal("Failed to get keys from badger kv store", err)
	}

	for _, key := range keys {
		fmt.Printf("key = %+v\n", key)
	}
}
