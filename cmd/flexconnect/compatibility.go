package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"flexconnect/internal/types"
)

func readATrustCompatibility(path string) (*types.ATrustCompatibility, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open aTrust compatibility file: %w", err)
	}
	defer f.Close()
	const maxSize = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, errors.New("aTrust compatibility file exceeds 64 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings *types.ATrustCompatibility
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("decode aTrust compatibility: %w", err)
	}
	if settings == nil {
		return nil, errors.New("aTrust compatibility must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("aTrust compatibility must contain one JSON object")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}
