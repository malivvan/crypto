package server

import (
	"io/ioutil"
	"log"
)

// Logger for the Assuan server-side diagnostics. Discarded by default.
var Logger log.Logger

func init() {
	Logger.SetPrefix("DEBUG(assuan/server): ")
	Logger.SetOutput(ioutil.Discard)
}
