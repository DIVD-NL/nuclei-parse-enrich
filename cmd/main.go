package main

/*
* https://www.DIVD.nl
* written by Pepijn van der Stap
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
	goflags := flags.NewParser(&options,
		flags.Default)

	parser := parser.Parser{}

	_, err := goflags.Parse()
	if err != nil {
		logrus.Fatal("Error parsing flags")
	}

	if noOutputProvided := options.Output == ""; noOutputProvided {
		options.Output = "output.json"
	}

	if options.Input == "" {
		stat, err := os.Stdin.Stat()

		if err != nil {
			logrus.Fatal("Error reading stdin")
		}

		if ok := (stat.Size() > 0); !ok {
			logrus.Fatal("No input provided")
		}

		parser = *parser.NewParser(os.Stdin)

	}

	if options.Input != "" {
		file, err := os.Open(options.Input)

		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()

		parser = *parser.NewParser(file)
	}

	parser.ProcessNucleiScan()

	parser.EnrichScanRecords()

	logrus.Debug("parser: EnrichScanRecords - ended")

	parser.MergeScanEnrichment()

	outputFile, err := os.Create(options.Output)

	if err != nil {
		logrus.Fatal(err)
	}

	defer parser.File.Close()

	parser.WriteOutput(outputFile)

	// parser.OutputWriter.Flush()

}
