package main

import (
	"github.com/bhangun/iket/pkg/plugins/auth"
)

// Plugin is the exported symbol for the plugin
var Plugin = auth.NewSAMLPlugin()
