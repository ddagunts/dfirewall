// +build testrunner

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// main function specifically for running integration tests
func main() {
	runner := &IntegrationTestRunner{
		verbose:  false,
		timeout:  30 * time.Minute,
		parallel: runtime.NumCPU(),
	}

	// Parse command line flags
	flag.BoolVar(&runner.verbose, "verbose", false, "Enable verbose output")
	flag.DurationVar(&runner.timeout, "timeout", 30*time.Minute, "Test timeout duration")
	flag.IntVar(&runner.parallel, "parallel", runtime.NumCPU(), "Number of parallel test processes")
	
	var skipCategoriesStr string
	var onlyCategoriesStr string
	flag.StringVar(&skipCategoriesStr, "skip", "", "Comma-separated list of test categories to skip")
	flag.StringVar(&onlyCategoriesStr, "only", "", "Comma-separated list of test categories to run (exclusive)")
	
	flag.Parse()

	if skipCategoriesStr != "" {
		runner.skipCategories = strings.Split(skipCategoriesStr, ",")
	}
	if onlyCategoriesStr != "" {
		runner.onlyCategories = strings.Split(onlyCategoriesStr, ",")
	}

	// Print test information
	runner.printTestInfo()

	// Run prerequisites check
	if err := runner.checkPrerequisites(); err != nil {
		log.Fatalf("Prerequisites check failed: %v", err)
	}

	// Run the tests
	exitCode := runner.runTests()
	os.Exit(exitCode)
}