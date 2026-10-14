package model

import "testing"

func TestCustomRulesAllowList(t *testing.T) {
	ok := []string{
		`SecRule ARGS "@contains x" "id:1001,phase:2,deny"`,
		"# comment\nSecRuleRemoveById 942100\nSecRule REQUEST_URI \"@beginsWith /a\" \\\n  \"id:1002,phase:1,pass,nolog\"",
	}
	for _, r := range ok {
		if err := checkCustomRules(r); err != nil {
			t.Errorf("%q: %v", r, err)
		}
	}
	bad := []string{
		"SecUploadDir /etc/cron.d\nSecUploadKeepFiles On",
		"SecAuditEngine On\nSecAuditLog /var/lib/x",
		"Include /etc/passwd",
		"SecDataDir /tmp",
		`SecRule ARGS "@pmf /etc/passwd" "id:1003,deny"`,
		`SecRule ARGS "@ipMatchF /etc/hosts" "id:1004,deny"`,
		`SecRule REMOTE_ADDR "@rbl x.example" "id:1005,deny"`,
		`SecRule ARGS "@pmFromFile a" "id:1006,deny"`,
	}
	for _, r := range bad {
		if err := checkCustomRules(r); err == nil {
			t.Errorf("accepted %q", r)
		}
	}
}
