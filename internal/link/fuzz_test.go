package link_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/XiaoYouChR/Kelpie/internal/link"
)

func FuzzParse(f *testing.F) {
	data, err := os.ReadFile("../../testdata/links.json")
	if err != nil {
		f.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		f.Fatal(err)
	}
	for _, v := range vectors {
		f.Add(v.Link)
	}
	f.Add("ed2k://|file|a|9728001|06329E9DBA1373512C06386FE29E3C65|p=D7DEF262A127CD79096A108E7A9FC138:47C61A0FA8738BA77308A8A600F88E4B|/")
	f.Add("ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|/|sources,1.2.3.4:4662,example.com:4662,[2001:db8::1]:4672,5.6.7.8:0|/")
	f.Add("ed2k://|file|a|5|31D6CFE0D16AE931B73C59D7E0C089C0|h=dztdjp5oxqbuqkmbawjd2dzg4r5kgp7v|/")
	f.Add("ed2k://%7Cfile%7Ca%7C5%7C31D6CFE0D16AE931B73C59D7E0C089C0%7C/")
	f.Fuzz(func(t *testing.T, text string) {
		file, err := link.Parse(text)
		if err != nil {
			if !errors.Is(err, link.ErrInvalid) {
				t.Fatalf("error %v does not wrap ErrInvalid", err)
			}
			return
		}
		if file.Name == "" || file.Size <= 0 {
			t.Fatalf("accepted %+v", file)
		}
	})
}
