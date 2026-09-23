package client

import (
	"io/ioutil"
	"log"
)

// Logger for the Assuan client-side diagnostics. Discarded by default.
var Logger log.Logger

func init() {
	Logger.SetPrefix("DEBUG(assuan/client): ")
	Logger.SetOutput(ioutil.Discard)
}
