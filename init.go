package main

import (
	"flag"
	"fmt"
	"os"
	"path"
)

func initProgram() error {
	err := initValue()
	if err != nil {
		return fmt.Errorf("init value: %w", err)
	}

	initFlag()
	args = flag.Args()
	if len(args) > 1 {
		subCmdArgs = args[1:]
	}
	
	args = flag.Args()

	return nil
}

func initDir(dirPath string) error {
	dirStat, err := os.Stat(dirPath)
	switch true {
	case os.IsNotExist(err):
		err := os.MkdirAll(dirPath, 0711)
		if err != nil {
			return fmt.Errorf("create key dirctory: %w", err)
		}

	case err != nil:
		return fmt.Errorf("stat dirctory: %w", err)

	case !dirStat.IsDir():
		return fmt.Errorf("stat dirctory: %v not a directory", dirPath)
	}

	return nil
}

func initFlag() {
	flag.StringVar(&keyType, "type", keyType, "key type")
	flag.IntVar(&keySize, "size", keySize, "key size")
	flag.StringVar(&privateKeyPathArg, "private", privateKeyPathArg, "private key file (default "+privateKeyPath+")")
	flag.StringVar(&publicKeyPathArg, "public", publicKeyPathArg, "public key file (default "+publicKeyPath+")")
	flag.Parse()
}

func initValue() error {
	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("load user directory: %w", err)
	}

	keyDir := path.Join(homeDirPath, keyDirName)

	err = initDir(keyDir)
	if err != nil {
		return fmt.Errorf("init directory: %w", err)
	}

	privateKeyPath = path.Join(keyDir, privatekeyName)
	publicKeyPath = path.Join(path.Dir(privateKeyPath), publicKeyName)

	return nil
}