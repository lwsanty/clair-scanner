package scanner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"gopkg.in/src-d/go-log.v1"

	"github.com/olekukonko/tablewriter"
)

type vulnerabilityReport struct {
	Image           string              `json:"image"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

func sortBySeverity(vulnerabilities []VulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] < SeverityMap[vulnerabilities[j].Severity]
	})
}

func formatStatus(status string) string {
	if status == "Approved" {
		return fmt.Sprintf(NoticeColor, status)
	}
	return fmt.Sprintf(ErrorColor, status)
}

func formatTableData(vulnerabilities []VulnerabilityInfo, unapproved []string) [][]string {
	formatted := make([][]string, len(vulnerabilities))
	for i, vulnerability := range vulnerabilities {
		status := "Approved"
		for _, u := range unapproved {
			if vulnerability.Vulnerability == u {
				status = "Unapproved"
			}
		}
		formatted[i] = []string{
			formatStatus(status),
			vulnerability.Severity + " " + vulnerability.Vulnerability,
			vulnerability.FeatureName,
			vulnerability.FeatureVersion,
			vulnerability.Description + "\n\n" + vulnerability.Link,
		}
	}
	return formatted
}

func printTable(vulnerabilities []VulnerabilityInfo, unapproved []string) {
	header := []string{"Status", "CVE Severity", "Package Name", "Package Version", "CVE Description"}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("-")
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.AppendBulk(formatTableData(vulnerabilities, unapproved))
	table.Render()
}

func filterApproved(vulnerabilities []VulnerabilityInfo, unapproved []string, reportAll bool) []VulnerabilityInfo {
	if reportAll {
		return vulnerabilities
	}

	vulns := make([]VulnerabilityInfo, 0)
	for _, vuln := range vulnerabilities {
		for _, u := range unapproved {
			if vuln.Vulnerability == u {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

func reportToConsole(imageName string, vulnerabilities []VulnerabilityInfo, unapproved []string, reportAll bool) {
	if len(vulnerabilities) > 0 {
		log.Warningf("Image [%s] contains %d total vulnerabilities", imageName, len(vulnerabilities))

		vulnerabilities = filterApproved(vulnerabilities, unapproved, reportAll)
		sortBySeverity(vulnerabilities)

		if len(unapproved) > 0 {
			log.Warningf("Image [%s] contains %d unapproved vulnerabilities", imageName, len(unapproved))
			printTable(vulnerabilities, unapproved)
		} else {
			log.Infof("Image [%s] contains NO unapproved vulnerabilities", imageName)
			if reportAll {
				printTable(vulnerabilities, unapproved)
			}
		}
	} else {
		log.Infof("Image [%s] contains NO unapproved vulnerabilities", imageName)
	}
}

// reportToFile writes the report to file
func reportToFile(imageName string, vulnerabilities []VulnerabilityInfo, unapproved []string, file string) {
	if file == "" {
		return
	}
	report := &vulnerabilityReport{
		Image:           imageName,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		log.Errorf(err, "Could not create a report: report is not proper JSON")
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		log.Errorf(err, "Could not create a report: could not write to file")
	}
}
