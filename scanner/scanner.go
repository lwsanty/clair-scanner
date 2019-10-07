package scanner

import (
	"os"
	"strings"

	"gopkg.in/src-d/go-log.v1"

	srv "github.com/lwsanty/clair-scanner/server"
)

type VulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            //[key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE description]
}

const tmpPrefix = "clair-scanner-"

type ScannerConfig struct {
	ImageName          string
	Whitelist          VulnerabilitiesWhitelist
	ClairURL           string
	ScannerIP          string
	ReportFile         string
	WhitelistThreshold string
	ReportAll          bool
	ExitWhenNoFeatures bool
}

// TODO return only required vulnerabilities
// Scan orchestrates the scanning process of an image
func Scan(config ScannerConfig) ([]string, []VulnerabilityInfo, error) {
	//Create a temporary folder where the docker image layers are going to be stored
	tmpPath := CreateTmpPath(tmpPrefix)
	defer os.RemoveAll(tmpPath)

	saveDockerImage(config.ImageName, tmpPath)
	layerIds := getImageLayerIds(tmpPath)

	log.Infof("layerIds: %v", layerIds)
	log.Infof("config.ClairURL: %v", config.ClairURL)
	log.Infof("config.ScannerIP: %v", config.ScannerIP)

	//Start a server that can serve Docker image layers to Clair
	server := srv.HttpFileServer(tmpPath)
	defer server.Shutdown(nil)

	//Analyze the layers
	if err := AnalyzeLayers(layerIds, config.ClairURL, config.ScannerIP); err != nil {
		return nil, nil, err
	}
	vulnerabilities := GetVulnerabilities(config, layerIds)

	if vulnerabilities == nil {
		return nil, nil, nil // exit when no features
	}

	//Check vulnerabilities against Whitelist and report
	unapproved := checkForUnapprovedVulnerabilities(config.ImageName, vulnerabilities, config.Whitelist, config.WhitelistThreshold)

	// Report vulnerabilities
	reportToConsole(config.ImageName, vulnerabilities, unapproved, config.ReportAll)
	reportToFile(config.ImageName, vulnerabilities, unapproved, config.ReportFile)

	return unapproved, vulnerabilities, nil
}

// checkForUnapprovedVulnerabilities checks if the found vulnerabilities are approved or not in the Whitelist
func checkForUnapprovedVulnerabilities(imageName string, vulnerabilities []VulnerabilityInfo, whitelist VulnerabilitiesWhitelist, whitelistThreshold string) []string {
	var unapproved []string
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].Vulnerability
		severity := vulnerabilities[i].Severity
		vulnerable := true

		//Check if the vulnerability has a severity less than our threshold severity
		if SeverityMap[severity] > SeverityMap[whitelistThreshold] {
			vulnerable = false
		}

		//Check if the vulnerability exists in the GeneralWhitelist
		if vulnerable {
			if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
				vulnerable = false
			}
		}

		//If not in GeneralWhitelist check if the vulnerability exists in the imageVulnerabilities
		if vulnerable && len(imageVulnerabilities) > 0 {
			if _, exists := imageVulnerabilities[vulnerability]; exists {
				vulnerable = false
			}
		}
		if vulnerable {
			unapproved = append(unapproved, vulnerability)
		}
	}
	return unapproved
}

// getImageVulnerabilities returns image specific Whitelist of vulnerabilities from whitelistImageVulnerabilities
func getImageVulnerabilities(imageName string, whitelistImageVulnerabilities map[string]map[string]string) map[string]string {
	var imageVulnerabilities map[string]string
	imageWithoutVersion := strings.Split(imageName, ":") // TODO there is a bug here if it is a private registry with a custom port registry:777/ubuntu:tag
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion[0]]; exists {
		imageVulnerabilities = val
	}
	return imageVulnerabilities
}
