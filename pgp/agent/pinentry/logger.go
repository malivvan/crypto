package pinentry

import (
	"io/ioutil"
	"log"
)

// Logger for the pinentry high-level diagnostics. Discarded by default.
var Logger log.Logger

func init() {
	Logger.SetPrefix("DEBUG(assuan/pinentry): ")
	Logger.SetOutput(ioutil.Discard)
}
