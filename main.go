package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const partByteSize = 17179870

func main() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load config, %v", err)
	}
	svc := s3.NewFromConfig(cfg)

	args := os.Args
	if len(args) < 3 {
		log.Fatalf("Usage: s3-hash-checker s3://my-s3-bucket/fileKey localFile\n")
	}
	args = args[1:]

	r := regexp.MustCompile(`s3://([^/]+)/(.*)`)
	matches := r.FindStringSubmatch(args[0])
	if len(matches) < 3 {
		log.Fatalf("invalid s3 file\n")
	}
	matches = matches[1:]

	attribs, err := svc.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
		Bucket: stringPtr(matches[0]),
		Key:    stringPtr(matches[1]),
		ObjectAttributes: []types.ObjectAttributes{
			types.ObjectAttributesChecksum,
			types.ObjectAttributesObjectParts,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	err = compareMultipartS3Local(
		attribs.ObjectParts.Parts,
		attribs.Checksum.ChecksumSHA256,
		args[1],
	)
	if err != nil {
		log.Fatal(err)
	}
}

func getHash(input []byte) []byte {
	h := sha256.New()

	h.Write(input)
	bs := h.Sum(nil)

	return bs
}

func compareMultipartS3Local(partsDetails []types.ObjectPart, overallChecksum *string, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}

	h := sha256.New()
	br := bufio.NewReader(f)

	appendedHash := []byte{}

	count := 0
	for {
		count++
		curr, err := br.ReadByte()

		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Println(err)
			break
		}

		if !errors.Is(err, io.EOF) {
			h.Write([]byte{curr})
		}

		if count%partByteSize == 0 || errors.Is(err, io.EOF) {
			partIndex := (count / partByteSize) - 1
			if count%partByteSize != 0 && errors.Is(err, io.EOF) {
				partIndex++
			}

			sum := h.Sum(nil)

			b, err := base64.StdEncoding.DecodeString(*partsDetails[partIndex].ChecksumSHA256)
			if err != nil {
				return err
			}

			result := ""
			if bytes.Equal(sum, b) {
				result = "✓"
			} else {
				result = "✗"
			}
			fmt.Printf("Part %v [%s]: %s\n", partIndex+1, result, *partsDetails[partIndex].ChecksumSHA256)

			appendedHash = append(appendedHash, sum...)
			h = sha256.New()
		}

		if err != nil {
			overall, err := base64.StdEncoding.DecodeString(*overallChecksum)
			if err != nil {
				return err
			}
			result := ""
			if bytes.Equal(getHash(appendedHash), overall) {
				result = "✓"
			} else {
				result = "✗"
			}
			fmt.Printf("All [%s]: %s\n", result, *overallChecksum)
			return nil
		}
	}

	return errors.New("an error occured")
}

func stringPtr(input string) *string {
	return &input
}
