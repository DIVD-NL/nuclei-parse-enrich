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
	for _, record := range p.ScanRecords {
		enricher := enricher.NewEnricher(record.Ip)
		enricher.Enrich()

		p.Enrichment = append(p.Enrichment, enricher.EnrichInfo)
	}
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
			if ok := record.Ip == enrichment.Ip; ok {
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

	flattened := make(map[string]interface{})
	for _, mergeResult := range p.MergeResults {
		flattened[mergeResult.EnrichInfo.Ip] = mergeResult
	}

	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ")
	encoder.Encode(flattened)

	logrus.Debug("parser: WriteOutput - ended")
}
