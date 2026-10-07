package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"flexconnect/client/local"
)

func runAuthentication(parent context.Context, client *local.Client, args []string, timeout time.Duration) error {
	if wantCommandHelp(args) {
		return printNamedHelp("auth")
	}
	action := "status"
	if len(args) > 0 {
		action, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(cliErr)
	stdin := fs.Bool("response-stdin", false, "read verification code from standard input")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (action != "status" && action != "respond") || (action == "status" && *stdin) {
		return errors.New("usage: flexconnect auth [status | respond [--response-stdin]]")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	challenge, err := client.Authentication(ctx)
	cancel()
	if err != nil {
		return err
	}
	if action == "status" {
		return printJSON(challenge)
	}
	if challenge == nil {
		return errors.New("no pending authentication request")
	}
	if challenge.Method != "sms" {
		return errors.New("authentication method is not supported")
	}
	if !time.Now().Before(challenge.ExpiresAt) {
		return errors.New("authentication request expired")
	}
	// Human input is outside ordinary HTTP deadlines. The daemon owns challenge expiry.
	var response string
	if *stdin {
		response, _, err = readSecretInput("", true, cliIn)
	} else {
		response, err = promptSecretValue(bufio.NewReader(cliIn), cliIn, cliOut, "SMS verification code")
	}
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(parent, timeout)
	defer cancel()
	if err := client.RespondAuthentication(ctx, challenge.ID, response); err != nil {
		return err
	}
	_, err = fmt.Fprintln(cliOut, "Verification code submitted.")
	return err
}
