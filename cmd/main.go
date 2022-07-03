package main

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"os"

	"nuclei-parse-enrich/pkg/parser"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
)

type Options struct {
	Input  string `short:"i" long:"input" description:"A file with the nuclei scan output" required:"false"`
	IPfile string `short:"f" long:"file" description:"A simple IP file with one IP address per line" required:"false"`
	Output string `short:"o" long:"output" description:"A file to write the enriched output to (default output.json)" required:"false"`
}

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
}

func main() {

	options := Options{}
	goflags := flags.NewParser(&options, flags.Default)

	scanParser := parser.Parser{}

	_, err := goflags.Parse()
	if err != nil {
		if errFlags, ok := err.(*flags.Error); ok && errFlags.Type == flags.ErrHelp {
			// flags automatically prints usage
			os.Exit(0)
		}
		logrus.Fatalf("Error parsing flags: %v", err)
	}

	if noOutputProvided := options.Output == ""; noOutputProvided {
		options.Output = "output.json"
	}

	if options.Input == "" && options.IPfile == "" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			logrus.Fatalf("Error getting stdin stat: %v", err)
		}
		if stat.Mode()&os.ModeNamedPipe == 0 {
			logrus.Fatalf("No input file provided and stdin is not a pipe")
		}

		scanParser = *scanParser.NewParser(os.Stdin)
	} else if options.IPfile != "" {
		file, err := os.Open(options.IPfile)
		if err != nil {
			logrus.Fatalf("Error opening ip file: %v", err)
		}
		defer file.Close()
		scanParser = *scanParser.NewSimpleParser(file)
	} else {
		file, err := os.Open(options.Input)

		if err != nil {
			logrus.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()

		scanParser = *scanParser.NewParser(file)
	}

	// If we have an IP file onyl, start the simple scan.
	// Else we asume it's a Nuclei .json file
	if options.IPfile != "" {
		scanParser.ProcessSimpleScan()
	} else {
		scanParser.ProcessNucleiScan()
	}

	scanParser.EnrichScanRecords()
	logrus.Debug("nucleiScanParser: EnrichScanRecords - ended")
	scanParser.MergeScanEnrichment()

	outputFile, err := os.Create(options.Output)

	if err != nil {
		logrus.Fatal(err)
	}

	defer scanParser.File.Close()

	scanParser.WriteOutput(outputFile)
}
