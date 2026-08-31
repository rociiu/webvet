package rules_test

import (
	"github.com/rociiu/webvet/rules"
	"testing"
)

func TestRegistry(t *testing.T) {
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(rules.KnownIDs()) != len(rules.MetadataList()) {
		t.Fatal("rule IDs are not unique")
	}
}
