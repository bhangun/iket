package main

import (
	"iket/plugins/auth"
)

// Plugin is the exported symbol for the plugin
var Plugin = auth.NewSAMLPlugin()
