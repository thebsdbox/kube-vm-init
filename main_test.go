package main_test

import (
	"reflect"
	"testing"

	main "github.com/thebsdbox/ginit"
)

func TestParseCmdLine(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		path    string
		want    map[string]string
		wantErr bool
	}{
		{name: "Test 1", path: "tests/cmdline1", want: map[string]string{"console": "hvc0", "dhcp": "true", "dns": "8.8.8.8", "entrypoint": "\"/docker-entrypoint.sh nginx\"", "hostname": "k8s", "init": "/init", "reboot": "t", "root": "/dev/vda"}, wantErr: false},
		{name: "Test 2", path: "tests/cmdline2", want: map[string]string{"console": "hvc0", "dhcp": "true", "dns": "8.8.8.8", "entrypoint": "\"/docker-entrypoint.sh nginx\"", "hostname": "k8s", "init": "/init", "reboot": "t", "root": "/dev/vda"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := main.ParseCmdLine(tt.path)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ParseCmdLine() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ParseCmdLine() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCmdLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

// [console:hvc0 dhcp:true dns:8.8.8.8 entrypoint:"/docker-entrypoint.sh nginx" hostname:k8s init:/init reboot:t root:/dev/vda]
// [console:hvc0 dhcp:true dns:8.8.8.8 entrypoint:"/docker-entrypoint.sh nginx" hostname:k8s init:/init reboot:t root:/dev/vda]
