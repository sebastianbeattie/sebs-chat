package main

var args struct {
	Command string `arg:"positional" help:"Command to execute"`
	Config  string `arg:"-c,--config" help:"Path to the config file" default:"config.json"`
	Input   string `arg:"-i,--input" help:"Path to JSON file"`
}
