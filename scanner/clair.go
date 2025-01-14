package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	v1 "github.com/coreos/clair/api/v1"
	"github.com/lwsanty/clair-scanner/server"
	"gopkg.in/src-d/go-log.v1"
)

const (
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
)

type VulnerabilityInfo struct {
	FeatureName    string `json:"featurename"`
	FeatureVersion string `json:"featureversion"`
	Vulnerability  string `json:"vulnerability"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	Link           string `json:"link"`
	Severity       string `json:"severity"`
	FixedBy        string `json:"fixedby"`
}

// analyzeLayer tells Clair which layers to analyze
func AnalyzeLayers(layerIds []string, clairURL string, scannerIP string) error {
	tmpPath := "http://" + scannerIP + ":" + server.HttpPort

	for i := 0; i < len(layerIds); i++ {
		log.Infof("Analyzing %s", layerIds[i])

		if i > 0 {
			if err := analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], layerIds[i-1]); err != nil {
				return err
			}
		} else {
			if err := analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], ""); err != nil {
				return err
			}
		}
	}

	return nil
}

// analyzeLayer pushes the required information to Clair to Scan the layer
func analyzeLayer(clairURL, path, layerName, parentLayerName string) error {
	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Errorf(err, "Could not analyze layer: payload is not JSON")
		return err
	}

	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Errorf(err, "Could not analyze layer: could not prepare request for Clair")
		return err
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Errorf(err, "Could not analyze layer: POST to Clair failed")
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		log.Errorf(err, "Could not analyze layer: Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
		return err
	}

	return nil
}

// getVulnerabilities fetches vulnerabilities from Clair and extracts the required information
func GetVulnerabilities(config ScannerConfig, layerIds []string) []VulnerabilityInfo {
	var vulnerabilities = make([]VulnerabilityInfo, 0)
	//Last layer gives you all the vulnerabilities of all layers
	rawVulnerabilities := fetchLayerVulnerabilities(config.ClairURL, layerIds[len(layerIds)-1])
	if len(rawVulnerabilities.Features) == 0 {
		if config.ExitWhenNoFeatures {
			log.Warningf("Could not fetch vulnerabilities. No features have been detected in the image. This usually means that the image isn't supported by Clair")
		}
		return nil
	}

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				vulnerability := VulnerabilityInfo{feature.Name, feature.Version, vulnerability.Name, vulnerability.NamespaceName, vulnerability.Description, vulnerability.Link, vulnerability.Severity, vulnerability.FixedBy}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities
}

// fetchLayerVulnerabilities fetches vulnerabilities from Clair
func fetchLayerVulnerabilities(clairURL string, layerID string) v1.Layer {
	response, err := http.Get(clairURL + fmt.Sprintf(getLayerFeaturesURI, layerID))
	if err != nil {
		log.Errorf(err, "Fetch vulnerabilities, Clair responded with a failure %v")
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		log.Errorf(err, "Fetch vulnerabilities, Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
	}

	var apiResponse v1.LayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		log.Errorf(err, "Fetch vulnerabilities, Could not decode response")
	} else if apiResponse.Error != nil {
		log.Errorf(err, "Fetch vulnerabilities, Response contains errors %s", apiResponse.Error.Message)
	}

	return *apiResponse.Layer
}
