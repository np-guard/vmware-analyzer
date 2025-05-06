package common

import "flag"

// a flag for writing/overriding the golden result files for tests
var Update = flag.Bool("update", false, "write or override golden files")
