package common

import (
	"io/ioutil"
	"log"
)

// Logger used for the low-level Assuan wire I/O diagnostics.
// It is discarded by default.
var Logger log.Logger

func init() {
	Logger.SetPrefix("DEBUG(assuan/common): ")
	Logger.SetOutput(ioutil.Discard)
}
