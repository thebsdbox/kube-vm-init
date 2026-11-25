package bpffsguard

import (
	"reflect"
	"strings"
	"testing"
)

func TestBPFFSMountPoints(t *testing.T) {
	mountinfo := strings.Join([]string{
		`22 1 0:21 / /sys rw,nosuid shared:7 - sysfs sysfs rw`,
		`30 22 0:26 / /sys/fs/bpf rw,nosuid shared:12 - bpf bpffs rw,mode=700`,
		`31 1 0:27 / /run/my\040bpf rw master:3 - bpf none rw`,
		`32 1 0:28 / /mnt/bpf-lookalike rw - tmpfs bpf rw`,
		`garbage`,
	}, "\n")

	got, err := bpffsMountPoints(strings.NewReader(mountinfo))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/sys/fs/bpf", "/run/my bpf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
