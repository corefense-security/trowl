package inventory

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestParseStatus(t *testing.T) {
	text := "Package: libcurl4\nVersion: 8.5.0-r0\nStatus: install ok installed\nSource: curl_8.5.0.bb\n\n" +
		"Package: zlib\nVersion: 1:1.3-r1\nStatus: install user installed\n\n" +
		"Package: libc6\nVersion: 2.36-9\nStatus: install ok installed\nSource: glibc (2.36-9)\n\n" +
		"Package: gone\nVersion: 1.0-r0\nStatus: deinstall ok config-files\n"
	want := []Component{{"curl", "8.5.0"}, {"glibc", "2.36"}, {"zlib", "1.3"}}
	if got := parseStatus(text); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseStatus() = %v, want %v", got, want)
	}
}

func TestHeaderString(t *testing.T) {
	data := "x\x00glibc-2.43-r1.src.rpm\x00"
	b := make([]byte, 8+32)
	binary.BigEndian.PutUint32(b, 2)
	binary.BigEndian.PutUint32(b[8:], 1000)
	binary.BigEndian.PutUint32(b[24:], 1044)
	binary.BigEndian.PutUint32(b[24+8:], 2)
	b = append(b, data...)
	if got := headerString(b, 1044); got != "glibc-2.43-r1.src.rpm" {
		t.Fatalf("headerString() = %q", got)
	}
	if m := sourceRpm.FindStringSubmatch("glibc-2.43+git1+1c9-r1.7.src.rpm"); m == nil || m[1] != "glibc" || m[2] != "2.43+git1+1c9" {
		t.Fatalf("sourceRpm = %v", m)
	}
}
