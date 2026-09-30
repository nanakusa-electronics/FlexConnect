//go:build linux

package main

// A system daemon cannot depend on a logged-in desktop Secret Service.
const defaultSecretStore = "file"
