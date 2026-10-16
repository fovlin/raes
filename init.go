package main

import (
	"fmt"
	"os"
)

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