package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/awslabs/aws-sdk-go/service/kms"
	"github.com/codahale/kmssig"
	"github.com/docopt/docopt-go"
)

const usage = `kms-sig signs files using the AWS Key Management Service.

Usage:
  kms-sig sign <key-id> <file> <sig> [--context=<k1=v2,k2=v2>]
  kms-sig verify <file> <sig> [--context=<k1=v2,k2=v2>]
  kms-sig version

Options:
  <key-id>      The ID of the KMS key to use.
  <file>        The file to sign or verify.
  <sig>         The signature file.
  -h --help     Show this help information.
  -v --version  Show the version information.
`

func main() {
	args, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		log.Fatal(err)
	}

	if args["version"] == true {
		fmt.Printf(
			"version: %s\ngoversion: %s\nbuildtime: %s\n",
			version, goVersion, buildTime,
		)
		return
	}

	var context map[string]string
	if s, ok := args["--context"].(string); ok {
		c, err := parseContext(s)
		if err != nil {
			panic(err)
		}
		context = c
	}

	if args["sign"] == true {
		kms := kms.New(nil)
		keyID := args["<key-id>"].(string)
		inFile := args["<file>"].(string)
		sigFile := args["<sig>"].(string)

		in, err := os.Open(inFile)
		if err != nil {
			panic(err)
		}
		defer in.Close()

		out, err := os.Create(sigFile)
		if err != nil {
			panic(err)
		}
		defer out.Close()

		sig, err := kmssig.Sign(kms, keyID, context, in)
		if err != nil {
			panic(err)
		}

		if _, err := out.Write(sig); err != nil {
			panic(err)
		}
	} else if args["verify"] == true {
		kms := kms.New(nil)
		inFile := args["<file>"].(string)
		sigFile := args["<sig>"].(string)

		in, err := os.Open(inFile)
		if err != nil {
			panic(err)
		}
		defer in.Close()

		sig, err := os.Open(sigFile)
		if err != nil {
			panic(err)
		}
		defer sig.Close()

		sigbuf, err := ioutil.ReadAll(sig)
		if err != nil {
			panic(err)
		}

		keyID, err := kmssig.Verify(kms, context, in, sigbuf)
		if err == kmssig.ErrInvalidSignature {
			fmt.Fprintln(os.Stderr, "invalid signature")
			os.Exit(1)
		} else if err != nil {
			panic(err)
		}

		fmt.Printf("valid signature from %s\n", keyID)
	} else {
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(-1)
	}
}

func parseContext(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}

	context := map[string]string{}
	for _, v := range strings.Split(s, ",") {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unable to parse context: %q", v)
		}
		context[parts[0]] = parts[1]
	}
	return context, nil
}
