package main

import (
	"fmt"
	"github.com/fovlin/opt"
	"os"
	"path"
	"strings"
)

func initProgram() error {
	err := initValue()
	if err != nil {
		return fmt.Errorf("init value: %w", err)
	}

	initFlag()
	args = opt.Args()
	if len(args) > 1 {
		subCmdArgs = args[1:]
	}

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
	opt.StringVar(&keyType, "t", "type", keyType)
	opt.StringVar(&privateKeyPathFlag, "i", "private-key", "")
	opt.StringVar(&publicKeyPathFlag, "p", "public-key", "")
	opt.Parse()

	if privateKeyPathFlag != "" {
		privateKeyPath = privateKeyPathFlag
	}

	if publicKeyPathFlag != "" {
		publicKeyPath = publicKeyPathFlag
	} else {
		publicKeyPath = path.Join(path.Dir(privateKeyPath), publicKeyName)
	}
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

func uniqueOutputPath(outputPath string) (string, error) {
	dir := path.Dir(outputPath)
	basePath := path.Base(outputPath)
	ext := path.Ext(basePath)
	pureName := strings.TrimSuffix(basePath, ext)

	for number := 0; ; number++ {
		candidatePath := outputPath
		if number > 0 {
			candidatePath = path.Join(dir, fmt.Sprint(pureName, "-", number, ext))
		}

		_, err := os.Stat(candidatePath)

		switch true {
		case os.IsNotExist(err):
			return candidatePath, nil

		case err != nil:
			return "", err
		}
	}
}
