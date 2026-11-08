package main

import (
	"strings"
	"testing"
)

const header = "target,system,service,owner,data_classification,data_shelf_life_years,migration_years,third_party,constraints\n"

func TestParseMapping(t *testing.T) {
	labels := ndmoPolicy().labels()

	t.Run("valid, BOM, reordered columns, label case, blank row", func(t *testing.T) {
		in := "\uFEFFowner,target,system,service,data_classification,data_shelf_life_years,migration_years,third_party,constraints\n" +
			"Web team,10.0.0.1:443,Portal,Login,secret,10,2.5,in-house,\"no downtime, ever\"\n" +
			",,,,,,,,\n" +
			"Ops,10.0.0.2:8443,Batch,,,,,Vendor X,\n"
		got, err := parseMapping(strings.NewReader(in), labels)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
		e := got[0]
		if e.Target != "10.0.0.1:443" || e.Owner != "Web team" || e.DataClassification != "Secret" || e.Constraints != "no downtime, ever" {
			t.Errorf("entry 0 = %+v", e)
		}
		if e.DataShelfLifeYears == nil || *e.DataShelfLifeYears != 10 || e.MigrationYears == nil || *e.MigrationYears != 2.5 {
			t.Errorf("years = %v %v", e.DataShelfLifeYears, e.MigrationYears)
		}
		if got[1].DataShelfLifeYears != nil || got[1].MigrationYears != nil {
			t.Errorf("empty years should be nil: %+v", got[1])
		}
	})

	bad := []struct{ name, in, want string }{
		{"empty file", "", "empty file"},
		{"unknown column", strings.Replace(header, "constraints", "notes", 1), `unknown column "notes"`},
		{"missing column", strings.Replace(header, ",constraints", "", 1), `missing column "constraints"`},
		{"no port", header + "10.0.0.1,a,b,c,Secret,,,in-house,\n", "must be host:port"},
		{"bad port", header + "10.0.0.1:99999,a,b,c,Secret,,,in-house,\n", "invalid port"},
		{"duplicate", header + "10.0.0.1:443,a,,,,,,,\n10.0.0.1:443,b,,,,,,,\n", "already on line 2"},
		{"unknown label", header + "10.0.0.1:443,a,,,Confidential,,,,\n", `"Confidential" is not one of`},
		{"negative years", header + "10.0.0.1:443,a,,,,-1,,,\n", "non-negative"},
		{"NaN years", header + "10.0.0.1:443,a,,,,NaN,,,\n", "non-negative"},
		{"short row", header + "10.0.0.1:443,a\n", "wrong number of fields"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMapping(strings.NewReader(tc.in), labels)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	t.Run("nil labels skip the classification check (scan --targets)", func(t *testing.T) {
		if _, err := parseMapping(strings.NewReader(header+"10.0.0.1:443,a,,,Anything,,,,\n"), nil); err != nil {
			t.Fatal(err)
		}
	})
}
