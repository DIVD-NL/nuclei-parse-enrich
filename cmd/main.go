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

	nucleiScanParser := parser.Parser{}

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

	if options.Input == "" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			logrus.Fatalf("Error getting stdin stat: %v", err)
		}
		if stat.Mode()&os.ModeNamedPipe == 0 {
			logrus.Fatalf("No input file provided and stdin is not a pipe")
		}

		nucleiScanParser = *nucleiScanParser.NewParser(os.Stdin)
	} else {
		file, err := os.Open(options.Input)

		if err != nil {
			logrus.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()

		nucleiScanParser = *nucleiScanParser.NewParser(file)
	}

	nucleiScanParser.ProcessNucleiScan()
	nucleiScanParser.EnrichScanRecords()

	logrus.Debug("nucleiScanParser: EnrichScanRecords - ended")

	nucleiScanParser.MergeScanEnrichment()

	outputFile, err := os.Create(options.Output)

	if err != nil {
		logrus.Fatal(err)
	}

	defer nucleiScanParser.File.Close()

	nucleiScanParser.WriteOutput(outputFile)
}
