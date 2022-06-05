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
	//"time"

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
	ipAddrs := make(map[string]struct{})
	for i, record := range p.ScanRecords {
		if record.Ip == "" {
			logrus.Warnf("scan record %d contains empty IP address, skipping: %+v", i, record)
			continue
		}
		ipAddrs[record.Ip] = struct{}{}
	}

	enricher := enricher.NewEnricher()
	limitCh := make(chan bool, 8) // XXX
	resultCh := make(chan types.EnrichInfo, 3)

	var wg sync.WaitGroup
	go func() {
		for res := range resultCh {
			//logrus.Debugf("received: %+v", res)
			p.Enrichment = append(p.Enrichment, res)
			wg.Done()
		}
	}()

	for ipAddr := range ipAddrs {
		wg.Add(1)
		ipAddr := ipAddr
		limitCh <- true
		go func() {
			//logrus.Infof("scheduled: %v", time.Now())
			wg.Add(1) // gets marked as Done in resultCh loop
			resultCh <- enricher.EnrichIP(ipAddr)
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

	mergeResult := types.MergeResult{}

	if len(p.Enrichment) < 1 {
		logrus.Debug("Length of ips in scan is ", len(p.ScanRecords))
		logrus.Fatal("No enrichment info to merge")
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

func (p *Parser) WriteOutput(outputFile *os.File) {
	logrus.Debug("parser: WriteOutput - start")

	flattened := make(map[string]types.MergeResult)
	for _, mergeResult := range p.MergeResults {
		flattened[mergeResult.EnrichInfo.Ip] = mergeResult
	}

	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ")
	encoder.Encode(flattened)

	logrus.Debug("parser: WriteOutput - ended")
}
