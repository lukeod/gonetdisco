package main

import (
	"testing"
)

// TestMain is a test that ensures the main package can be imported and included in tests.
// This is a minimal test to ensure the main package is testable.
func TestMain(t *testing.T) {
	// This test doesn't do anything specific, it just ensures that the main package
	// can be imported without errors.
	t.Log("Main package can be imported successfully")
}