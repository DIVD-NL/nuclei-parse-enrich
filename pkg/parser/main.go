package parser

/*
* https://www.DIVD.nl
* written by Pepijn van der Stap
 */

import (
	"encoding/json"
	"io"
	"nuclei-parse-enrich/pkg/enricher"
	"nuclei-parse-enrich/pkg/types"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

type Parser struct {
	*json.Decoder
	*os.File
	Enrichment   []types.EnrichInfo
	ScanRecords  []types.NucleiJsonRecord
	MergeResults []types.MergeResult
}

func (p *Parser) NewParser(file *os.File) *Parser {
	return &Parser{
		Decoder: json.NewDecoder(file),
		File:    file,
	}
}

func (p *Parser) ProcessNucleiScan() {
	logrus.Debug("parser: ProcessNucleiScan - started parsing: ", p.File.Name())
	for {
		var record types.NucleiJsonRecord
		err := p.Decode(&record)
		if err != nil {
			if err == io.EOF {
				break
			}
			logrus.Debug(err)
		}
		p.ScanRecords = append(p.ScanRecords, record)
	}

	logrus.Debug("parser: ProcessNucleiScan - ended parsing ", len(p.ScanRecords), " records")
}

func (p *Parser) EnrichScanRecords() {
	logrus.Debug("parser: MergeScanEnrichment - start")
	enricher := enricher.NewEnricher()

	ipAddrsAndHostnames := []map[string]string{}

	for i, record := range p.ScanRecords {
		if record.Ip == "" {
			logrus.Warnf("scan record %d contains empty IP address, skipping: %+v", i, record)
			continue
		}

		ipAddrsAndHostnames = append(ipAddrsAndHostnames, map[string]string{
			"ip":   record.Ip,
			"host": record.Host,
		})

	}

	limitCh := make(chan bool, 8) // Ripe API limit is 8 concurrent requests
	resultCh := make(chan types.EnrichInfo, len(ipAddrsAndHostnames))
	seenIps := map[string]bool{}

	var wg sync.WaitGroup
	go func() {
		for res := range resultCh {
			p.Enrichment = append(p.Enrichment, res)
			wg.Done()
		}
	}()

	for _, record := range ipAddrsAndHostnames {
		wg.Add(1)
		ipAddr := record["ip"]
		limitCh <- true // block if limit is reached
		go func() {
			if !seenIps[ipAddr] {
				wg.Add(1) // gets marked as Done in resultCh loop
				enricher.EnrichIP(ipAddr)
				resultCh <- enricher.EnrichIP(ipAddr)
				<-limitCh
			} else {
				logrus.Debug("parser: EnrichScanRecords - skipped IP: ", ipAddr)
			}
			seenIps[ipAddr] = true
			wg.Done()
		}()
	}

	wg.Wait()
	close(resultCh)
	close(limitCh)
}

func (p *Parser) MergeScanEnrichment() {
	mergeResult := types.MergeResult{}
	seenHosts := map[string]bool{}

	if len(p.Enrichment) < 1 {
		logrus.Debug("Length of ips in scan is ", len(p.ScanRecords))
		logrus.Fatal("No enrichment info to merge")
	}

	for _, record := range p.ScanRecords {
		if seenHosts[record.Host] {
			logrus.Debug("parser: MergeScanEnrichment - skipping duped virtual host: ", record.Host)
			continue
		}

		for _, enrichment := range p.Enrichment {
			seenHosts[record.Host] = true

			mergeResult.EnrichInfo = enrichment
			mergeResult.NucleiJsonRecord = record
			p.MergeResults = append(p.MergeResults, mergeResult)
			break
		}
	}

}

func (p *Parser) WriteOutput(outputFile *os.File) {

	flattened := []types.MergeResult{}
	flattened = append(flattened, p.MergeResults...)

	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ")
	encoder.Encode(flattened)

	logrus.Debug("parser: WriteOutput - finished writing ", len(flattened), " records")
}
