package main

import (
	"fmt"
	"os"

	"gopkg.in/src-d/go-log.v1"

	cli "github.com/jawher/mow.cli"
	"github.com/lwsanty/clair-scanner/scanner"
	"github.com/mbndr/logo"
)

var (
	whitelist = scanner.VulnerabilitiesWhitelist{}
	logger    *logo.Logger
)

func main() {
	app := cli.App("clair-scanner", "Scan local Docker images for vulnerabilities with Clair")

	var (
		whitelistFile      = app.StringOpt("w whitelist", "", "Path to the whitelist file")
		whitelistThreshold = app.StringOpt("t threshold", "Unknown", "CVE severity threshold. Valid values; 'Defcon1', 'Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'")
		clair              = app.StringOpt("c clair", "http://127.0.0.1:6060", "Clair URL")
		ip                 = app.StringOpt("ip", "localhost", "IP address where clair-scanner is running on")
		logFile            = app.StringOpt("l log", "", "Log to a file")
		reportAll          = app.BoolOpt("all reportAll", true, "Display all vulnerabilities, even if they are approved")
		reportFile         = app.StringOpt("r report", "", "Report output file, as JSON")
		imageName          = app.StringArg("IMAGE", "", "Name of the Docker image to Scan")
		exitWhenNoFeatures = app.BoolOpt("exit-when-no-features", false, "Exit with status code 5 when no features are found for a particular image")
	)

	app.Before = func() {
		initializeLogger(*logFile)
		if *whitelistFile != "" {
			whitelist = scanner.ParseWhitelistFile(*whitelistFile)
		}
		scanner.ValidateThreshold(*whitelistThreshold)
	}

	app.Action = func() {
		logger.Info("Start clair-scanner")

		go scanner.ListenForSignal(func(s os.Signal) {
			log.Warningf("Application interrupted [%v]", s)
		})

		result, err := scanner.Scan(scanner.ScannerConfig{
			*imageName,
			whitelist,
			*clair,
			*ip,
			*reportFile,
			*whitelistThreshold,
			*reportAll,
			*exitWhenNoFeatures,
		})
		if err != nil {
			os.Exit(1)
		} else if result == nil {
			os.Exit(5)
		} else if len(result) > 0 {
			os.Exit(1)
		}
	}
	app.Run(os.Args)
}

func initializeLogger(logFile string) {
	cliRec := logo.NewReceiver(os.Stderr, "")
	cliRec.Color = true

	if logFile != "" {
		file, err := logo.Open(logFile)
		if err != nil {
			fmt.Printf("Could not initialize logging file %v", err)
			os.Exit(1)
		}

		fileRec := logo.NewReceiver(file, "")
		logger = logo.NewLogger(cliRec, fileRec)
	} else {
		logger = logo.NewLogger(cliRec)
	}
}
