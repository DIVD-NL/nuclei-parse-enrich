package parser

/*
* https://www.DIVD.nl
* written by Pepijn van der Stap
 */

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"nuclei-parse-enrich/pkg/enricher"
	"nuclei-parse-enrich/pkg/types"
	"os"
	"reflect"

	"github.com/sirupsen/logrus"
)

type Parser struct {
	*json.Decoder
	*os.File
	Enrichment   []types.EnrichInfo
	ScanRecords  []types.NucleiJsonRecord
	MergeResults []types.MergeResult
	OutputWriter *csv.Writer
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

func (p *Parser) WriteOutput() {
	logrus.Debug("parser: WriteOutput - start")

	headerLine := []string{}

	scanHeader := reflect.TypeOf(p.MergeResults[0].NucleiJsonRecord)
	enrichHeader := reflect.TypeOf(p.MergeResults[0].EnrichInfo)

	for i := 0; i < scanHeader.NumField(); i++ {
		headerLine = append(headerLine, scanHeader.Field(i).Name)
	}

	for i := 0; i < enrichHeader.NumField(); i++ {
		if !contains(headerLine, enrichHeader.Field(i).Name) {
			headerLine = append(headerLine, enrichHeader.Field(i).Name)
		}
	}

	for i := 0; i < len(headerLine); i++ {
		headerLine[i] = "'" + headerLine[i] + "'"
	}

	p.OutputWriter.Write(headerLine)

	for _, record := range p.MergeResults {
		line := []string{}

		scanFields := reflect.ValueOf(record.NucleiJsonRecord)
		enrichFields := reflect.ValueOf(record.EnrichInfo)

		for i := 0; i < scanFields.NumField(); i++ {
			if scanFields.Type().Field(i).Name == "MatcherStatus" {
				line = append(line, fmt.Sprintf("%v", scanFields.Field(i).Interface()))
			} else if scanFields.Type().Field(i).Name == "Info" {
				info, err := json.Marshal(scanFields.Field(i).Interface())
				if err != nil {
					logrus.Debug(err)
				}
				line = append(line, string(info))
			} else {
				line = append(line, fmt.Sprintf("%v", scanFields.Field(i).Interface()))
			}
		}

		for i := 0; i < enrichFields.NumField(); i++ {
			if !contains(line, enrichFields.Field(i).String()) {
				line = append(line, enrichFields.Field(i).String())
			}
		}

		for i := 0; i < len(line); i++ {
			line[i] = "'" + line[i] + "'"
		}

		p.OutputWriter.Write(line)
	}

	p.OutputWriter.Flush()
	logrus.Debug("parser: WriteOutput - end")
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
