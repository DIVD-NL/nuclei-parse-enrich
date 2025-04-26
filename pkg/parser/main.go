package parser

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/enricher"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/types"

	"github.com/sirupsen/logrus"
)

type Parser struct {
	*json.Decoder
	*os.File
	Enrichment   []types.EnrichInfo
	SimpleIPs    []types.SimpleIPRecord
	ScanRecords  []types.NucleiJsonRecord
	MergeResults []types.MergeResult
}

func (p *Parser) NewSimpleParser(file *os.File) *Parser {
	return &Parser{
		File: file,
	}
}

func (p *Parser) NewParser(file *os.File) *Parser {
	return &Parser{
		Decoder: json.NewDecoder(file),
		File:    file,
	}
}

func (p *Parser) ProcessSimpleScan() error {
	logrus.Debug("parser: ProcessSimpleScan - started parsing: ", p.File.Name())
	scanner := bufio.NewScanner(p.File)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			logrus.Errorf("Error scanning file: %v", err)
			return fmt.Errorf("error scanning file: %w", err)
		}

		line := scanner.Text()
		// Skip empty lines or lines that are too long to be valid IPs
		if line == "" || len(line) > 45 {
			continue
		}

		// Check if the line contains a valid IP address
		ip := net.ParseIP(line)
		if ip == nil {
			logrus.Debugf("parser: ProcessSimpleScan - skipping invalid IP: %s", line)
			continue
		}

		var record types.NucleiJsonRecord
		record.Ip = line
		p.ScanRecords = append(p.ScanRecords, record)
	}

	if err := scanner.Err(); err != nil {
		logrus.Errorf("Error at end of scanning: %v", err)
		return fmt.Errorf("error at end of scanning: %w", err)
	}

	logrus.Debugf("parser: ProcessSimpleScan - parsed %d valid IP addresses", len(p.ScanRecords))
	return nil
}

func (p *Parser) ProcessNucleiScan() {
	logrus.Debug("parser: ProcessNucleiScan - started parsing: ", p.File.Name())

	// First, try to read the entire file content
	fileContent, err := io.ReadAll(p.File)
	if err != nil {
		logrus.Fatalf("Error reading file: %v", err)
	}

	// Try to parse as a map (old format)
	var recordMap map[string]types.NucleiJsonRecord
	err = json.Unmarshal(fileContent, &recordMap)

	if err == nil {
		// Successfully parsed as a map, extract records
		logrus.Debug("parser: ProcessNucleiScan - parsed as map format")
		for ip, record := range recordMap {
			// Ensure the IP is set if it's missing
			if record.Ip == "" {
				record.Ip = ip
			}
			p.ScanRecords = append(p.ScanRecords, record)
		}
	} else {
		// Try to parse as an array of objects (newer format)
		var recordsArray []types.NucleiJsonRecord
		err = json.Unmarshal(fileContent, &recordsArray)

		if err == nil {
			// Successfully parsed as array
			logrus.Debug("parser: ProcessNucleiScan - parsed as array format")
			p.ScanRecords = append(p.ScanRecords, recordsArray...)
		} else {
			// Try to parse as a single object
			var singleRecord types.NucleiJsonRecord
			err = json.Unmarshal(fileContent, &singleRecord)

			if err == nil && singleRecord.Ip != "" {
				// Successfully parsed as a single object
				logrus.Debug("parser: ProcessNucleiScan - parsed as single object format")
				p.ScanRecords = append(p.ScanRecords, singleRecord)
			} else {
				// Failed to parse in any known format
				logrus.Errorf("parser: ProcessNucleiScan - failed to parse file: %v", err)
				return
			}
		}
	}

	// Ensure we have IP addresses for all records
	for i, record := range p.ScanRecords {
		if record.Ip == "" {
			logrus.Debugf("parser: ProcessNucleiScan - record %d missing IP address", i)
		}
	}

	logrus.Debug("parser: ProcessNucleiScan - ended parsing ", len(p.ScanRecords), " records")
}

func (p *Parser) EnrichScanRecords() {
	uniqueIPAddresses := make(map[string]struct{})

	for _, record := range p.ScanRecords {
		ip := net.ParseIP(record.Ip)
		if ip == nil {
			logrus.Debug("parser: EnrichScanRecords - skipping invalid IP address: ", record.Ip)
			continue
		}
		if !ip.IsGlobalUnicast() {
			logrus.Debug("parser: EnrichScanRecords - skipping non-global IP address: ", record.Ip)
			continue
		}
		if ip.IsPrivate() {
			logrus.Debug("parser: EnrichScanRecords - skipping private IP address: ", record.Ip)
			continue
		}
		uniqueIPAddresses[record.Ip] = struct{}{}
	}

	logrus.Debugf("parser: EnrichScanRecords - found %d unique IP addresses", len(uniqueIPAddresses))
	if len(uniqueIPAddresses) == 0 {
		logrus.Warn("parser: EnrichScanRecords - no valid IP addresses found to enrich")
		return
	}

	nucleiEnricher := enricher.NewEnricher()

	limitCh := make(chan bool, 8)
	resultCh := make(chan types.EnrichInfo, 3)

	var wg sync.WaitGroup

	go func() {
		for enrichResult := range resultCh {
			p.Enrichment = append(p.Enrichment, enrichResult)
			wg.Done()
		}
	}()

	for ipAddr := range uniqueIPAddresses {
		logrus.Debug("enriching IP: ", ipAddr)
		wg.Add(1)
		ipAddr := ipAddr
		limitCh <- true
		go func() {
			wg.Add(1) // gets marked as Done in resultCh loop
			resultCh <- nucleiEnricher.EnrichIP(ipAddr)
			<-limitCh
			wg.Done()
		}()
	}
	wg.Wait()
	close(resultCh)
	close(limitCh)
}

func (p *Parser) MergeScanEnrichment() {
	logrus.Debug("parser: MergeScanEnrichment - start")
	var mergeResult = types.MergeResult{}

	if len(p.Enrichment) < 1 {
		logrus.Debug("Length of ips in scan is ", len(p.ScanRecords))
		// Instead of fatal, we'll create placeholder enrichment entries
		logrus.Warn("No enrichment info to merge, creating placeholder entries")

		// Create placeholder enrichment entries for each scan record
		for _, record := range p.ScanRecords {
			if record.Ip != "" {
				placeholder := types.EnrichInfo{
					Ip:          record.Ip,
					AbuseSource: "placeholder",
					Abuse:       "unknown",
					Prefix:      "unknown",
					Asn:         "unknown",
					Holder:      "unknown",
					Country:     "unknown",
					City:        "unknown",
				}
				p.Enrichment = append(p.Enrichment, placeholder)
			}
		}

		// If we still have no enrichment data, return empty results
		if len(p.Enrichment) < 1 {
			logrus.Warn("Unable to create any placeholder enrichment data")
			return
		}
	}

	for _, record := range p.ScanRecords {
		for _, enrichment := range p.Enrichment {
			if record.Ip == enrichment.Ip {
				mergeResult.EnrichInfo = enrichment
				mergeResult.NucleiJsonRecord = record
				p.MergeResults = append(p.MergeResults, mergeResult)
			}
		}
	}

	logrus.Debug("parser: MergeScanEnrichment - merged ", len(p.MergeResults), " records")
}

func (p *Parser) WriteOutput(outputFile *os.File) error {
	// Create a map with IP as key, preserving the original JSON structure
	mergeResultsMap := make(map[string]types.MergeResult)

	if len(p.MergeResults) == 0 {
		logrus.Warn("parser: WriteOutput - no merged results to write")
		// Write an empty JSON object at minimum
		_, err := outputFile.WriteString("{}\n")
		if err != nil {
			return fmt.Errorf("error writing output: %v", err)
		}
		return nil
	}

	// Use the IP as the key to preserve indexing
	for _, mergeResult := range p.MergeResults {
		if mergeResult.NucleiJsonRecord.Ip != "" {
			mergeResultsMap[mergeResult.NucleiJsonRecord.Ip] = mergeResult
		} else {
			// Fallback to a generated key if IP is missing
			randomKey := fmt.Sprintf("record_%d", len(mergeResultsMap))
			mergeResultsMap[randomKey] = mergeResult
			logrus.Warnf("No IP address found for record, using generated key: %s", randomKey)
		}
	}

	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(mergeResultsMap)

	if err != nil {
		return fmt.Errorf("error writing output: %v", err)
	}

	logrus.Debug("parser: WriteOutput - ended")
	return nil
}
