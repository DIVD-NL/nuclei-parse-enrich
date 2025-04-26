package main

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/parser"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	Input  string `short:"i" long:"input" description:"A file with the nuclei scan output" required:"false"`
	IPfile string `short:"f" long:"file" description:"A simple IP file with one IP address per line" required:"false"`
	Output string `short:"o" long:"output" description:"A file to write the enriched output to (default output_TIMESTAMP.json)" required:"false"`
	Debug  bool   `short:"d" long:"debug" description:"Enable debug logging" required:"false"`
}

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetFormatter(&logrus.TextFormatter{ // json would be better
		DisableColors: true,
		FullTimestamp: true,
	})
}

// detectFileFormat checks if the file contains JSON or a list of IPs
func detectFileFormat(filePath string) (string, error) {
	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Trim whitespace
	trimmed := strings.TrimSpace(string(content))
	if len(trimmed) > 0 {
		if trimmed[0] == '{' || trimmed[0] == '[' {
			// It's likely JSON
			var js interface{}
			if err := json.Unmarshal([]byte(trimmed), &js); err == nil {
				return "json", nil
			}
		}
	}

	// Otherwise, try to see if it's a list of IPs
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ipFound := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // Skip comments and empty lines
			// Check for IP format - very basic check
			if strings.Count(line, ".") == 3 {
				parts := strings.Split(line, ".")
				validIP := true
				for _, part := range parts {
					if part == "" {
						validIP = false
						break
					}
				}
				if validIP {
					ipFound = true
					break
				}
			}
		}
	}

	if ipFound {
		return "ip-list", nil
	}

	return "unknown", nil
}

func main() {
	options := Options{}
	goFlags := flags.NewParser(&options, flags.Default)

	scanParser := parser.Parser{}

	_, err := goFlags.Parse()
	if err != nil {
		if errFlags, ok := err.(*flags.Error); ok && errFlags.Type == flags.ErrHelp {
			// flags automatically prints usage
			os.Exit(0)
		}
		logrus.Fatalf("Error parsing flags: %v", err)
	}

	// Set debug logging if requested
	if options.Debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("Debug logging enabled")
	}

	if noOutputProvided := options.Output == ""; noOutputProvided {
		// Create a timestamped output filename
		timestamp := time.Now().Format("2006-01-02T15-04-05")
		options.Output = fmt.Sprintf("output_%s.json", timestamp)
	}

	// Handle stdin input
	if options.Input == "" && options.IPfile == "" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			logrus.Fatalf("Error getting stdin stat: %v", err)
		}
		if stat.Mode()&os.ModeNamedPipe == 0 {
			logrus.Fatalf("No input file provided and stdin is not a pipe")
		}

		scanParser = *scanParser.NewParser(os.Stdin)
		logrus.Info("Processing nuclei scan output from stdin")
		scanParser.ProcessNucleiScan()
	} else {
		// Handle file input - try to auto-detect the format if needed
		inputFile := options.Input
		if inputFile == "" {
			inputFile = options.IPfile
		}

		// Detect the file format
		fileFormat, err := detectFileFormat(inputFile)
		if err != nil {
			logrus.Fatalf("Error detecting file format: %v", err)
		}

		file, err := os.Open(inputFile)
		if err != nil {
			logrus.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()

		if fileFormat == "json" {
			logrus.Infof("Detected JSON format, processing as nuclei scan output: %s", inputFile)
			scanParser = *scanParser.NewParser(file)
			scanParser.ProcessNucleiScan()
		} else if fileFormat == "ip-list" || options.IPfile != "" {
			logrus.Infof("Processing file as IP list: %s", inputFile)
			scanParser = *scanParser.NewSimpleParser(file)
			scanParser.ProcessSimpleScan()
		} else {
			logrus.Fatalf("Unable to determine file format for: %s", inputFile)
		}
	}

	logrus.Infof("nucleiScanParser: EnrichScanRecords - started working on %d records", len(scanParser.ScanRecords))
	scanParser.EnrichScanRecords()

	logrus.Info("nucleiScanParser: EnrichScanRecords - ended")
	scanParser.MergeScanEnrichment()

	outputFile, err := os.Create(options.Output)
	if err != nil {
		logrus.Fatal(err)
	}

	defer scanParser.File.Close()
	defer outputFile.Close()

	logrus.Infof("Writing output to %s", options.Output)
	err = scanParser.WriteOutput(outputFile)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infof("Successfully processed %d records and saved results to %s", len(scanParser.MergeResults), options.Output)
}
