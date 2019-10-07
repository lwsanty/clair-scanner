package scanner

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/src-d/go-log.v1"

	"gopkg.in/yaml.v2"
)

const (
	InfoColor    = "\033[1;34m%s\033[0m"
	NoticeColor  = "\033[1;36m%s\033[0m"
	WarningColor = "\033[1;33m%s\033[0m"
	ErrorColor   = "\033[1;31m%s\033[0m"
	DebugColor   = "\033[0;36m%s\033[0m"
)

// Exported var used as mapping on CVE severity name to implied ranking
var SeverityMap = map[string]int{
	"Defcon1":    1,
	"Critical":   2,
	"High":       3,
	"Medium":     4,
	"Low":        5,
	"Negligible": 6,
	"Unknown":    7,
}

// ListenForSignal listens for interactions and executes the desired code when it happens
func ListenForSignal(fn func(os.Signal)) {
	signalChannel := make(chan os.Signal, 0)

	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGQUIT)
	for {
		execute := <-signalChannel
		fn(execute)
	}
}

// CreateTmpPath creates a temporary folder with a prefix
func CreateTmpPath(tmpPrefix string) string {
	tmpPath, err := ioutil.TempDir("", tmpPrefix)
	if err != nil {
		log.Errorf(err, "Could not create temporary folder: %s")
	}
	return tmpPath
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func Untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		if !strings.HasPrefix(path, filepath.Clean(target)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", header.Name)
		}
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, tarReader); err != nil {
			return err
		}
	}
	return nil
}

// parseWhitelistFile reads the Whitelist file and parses it
func ParseWhitelistFile(whitelistFile string) VulnerabilitiesWhitelist {
	whitelistTmp := VulnerabilitiesWhitelist{}

	whitelistBytes, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		log.Errorf(err, "Could not parse Whitelist file, could not read file %v")
	}
	if err = yaml.Unmarshal(whitelistBytes, &whitelistTmp); err != nil {
		log.Errorf(err, "Could not parse Whitelist file, could not unmarshal %v")
	}
	return whitelistTmp
}

// Validate that the given CVE severity threshold is a valid severity
func ValidateThreshold(threshold string) {
	for severity := range SeverityMap {
		if threshold == severity {
			return
		}
	}
	log.Warningf("Invalid CVE severity threshold %s given", threshold)
}
