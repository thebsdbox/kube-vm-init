package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/thebsdbox/ginit/pkg/bpffsguard"
	"github.com/thebsdbox/ginit/pkg/realm"
	"golang.org/x/sys/unix"
	"log/slog"
)

// bpffsGuard keeps the bpffs bind mount guard's eBPF programs attached for
// the lifetime of init.
var bpffsGuard *bpffsguard.Guard

func main() {
	if port := os.Getenv("GINIT_VSOCK_SERVICE"); port != "" {
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
			slog.Error(fmt.Sprintf("disable vsock service core dumps: %v", err))
			os.Exit(1)
		}
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			slog.Error(fmt.Sprintf("disable vsock service dumping: %v", err))
			os.Exit(1)
		}
		listener, err := startVSockProxy(port)
		if err != nil {
			slog.Error(fmt.Sprintf("vsock service: %v", err))
			os.Exit(1)
		}
		defer listener.Close()
		ready := os.NewFile(3, "vsock-ready")
		if _, err := ready.Write([]byte{0}); err != nil {
			slog.Error(fmt.Sprintf("report vsock readiness: %v", err))
			os.Exit(1)
		}
		ready.Close()
		select {}
	}
	if err := enterChrootStage(); err != nil {
		slog.Error(fmt.Sprintf("chroot stage error: %v", err))
		os.Exit(1)
	}

	// Fuck it

	//cmd.Execute()
	m := realm.DefaultMounts()
	d := realm.DefaultDevices()
	dev := m.GetMount("dev")
	dev.CreateMount = true
	dev.EnableMount = true

	proc := m.GetMount("proc")
	proc.CreateMount = true
	proc.EnableMount = true

	tmp := m.GetMount("tmp")
	tmp.CreateMount = true
	tmp.EnableMount = true

	sys := m.GetMount("sys")
	sys.CreateMount = true
	sys.EnableMount = true

	varF := m.GetMount("var")
	varF.CreateMount = true
	varF.EnableMount = true

	// Create all folders
	m.CreateFolder()
	// Ensure that /dev is mounted (first)
	err := m.MountNamed("dev", true)
	if err != nil {
		slog.Error(fmt.Sprintf("Error mounting dev: [%v]", err))
	}

	// Create all devices
	err = d.CreateDevice()
	if err != nil {
		slog.Error(fmt.Sprintf("Error creating device: [%v]", err))
	}

	// Mount any additional mounts
	err = m.MountAll()
	if err != nil {
		slog.Error(fmt.Sprintf("Error mounting: [%v]", err))
	}

	// HERE IS WHERE THE MAIN CODE GOES
	slog.Info("Starting ginit")
	//time.Sleep(time.Second * 2)

	//	log.Infoln("Beginning provisioning process")

	mac, err := realm.GetMAC()
	if err != nil {
		slog.Error(err.Error())
		//realm.Shell()
	}
	slog.Info(fmt.Sprintf("eth0 mac %s", mac))

	stuffs, err := ParseCmdLine(CmdlinePath)
	if err != nil {
		slog.Error(err.Error())
	}

	if stuffs["dhcp"] == "true" {
		slog.Info("Starting DHCP client")
		go realm.DHCPClient()
	}

	// Make every mount private before spawning anything. The chroot stage
	// inherits private copies, so it no longer changes propagation itself
	// (which the bpffs guard would deny for non-exempt processes).
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		slog.Error(fmt.Sprintf("Error marking mounts private: [%v]", err))
	}

	bpffsGuard, err = bpffsguard.Start(bpffsguard.Options{})
	if err != nil {
		slog.Error(fmt.Sprintf("bpffs guard error: [%v]", err))
	} else {
		slog.Info(fmt.Sprintf("bpffs bind mount guard active (%s)", bpffsGuard.Mode()))
	}

	err = startTetragon()
	if err != nil {
		slog.Error(fmt.Sprintf("Tetragon error: [%v]", err))
	}

	_, err = realm.MountRootVolume(stuffs["newroot"])
	if err != nil {
		slog.Error(fmt.Sprintf("Disk Error: [%v]", err))
	}

	if stuffs["hostname"] != "" {
		slog.Info(fmt.Sprintf("Setting hostname to %s", stuffs["hostname"]))
		err = realm.SetHostname(stuffs["hostname"])
		if err != nil {
			slog.Error(fmt.Sprintf("Error setting hostname: [%v]", err))
		}
	}

	if stuffs["dns"] != "" {
		slog.Info(fmt.Sprintf("Setting DNS to %s", stuffs["dns"]))
		err = realm.SetDNS(stuffs["dns"])
		if err != nil {
			slog.Error(fmt.Sprintf("Error setting DNS: [%v]", err))
		}
	}
	self, err := os.Executable()
	if err != nil {
		slog.Error(fmt.Sprintf("unable to resolve current executable: [%v]", err))
		realm.Shell()
		realm.Reboot()
	}

	cmd := exec.Command(self)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		"GINIT_CHROOT=/mnt",
		fmt.Sprintf("GINIT_ENTRYPOINT=%s", stuffs["entrypoint"]),
		fmt.Sprintf("GINIT_VSOCK_PORT=%s", stuffs["ginit.vsock_port"]),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	go func() {
		s := <-sigc
		if s == syscall.SIGTERM {
			slog.Info("Restarting")
			realm.Reboot()
		}
		fmt.Println(s.String()) // ... do something ...|||
	}()
	err = cmd.Start()
	if err != nil {
		slog.Error(fmt.Sprintf("command error [%v]", err))
	}
	err = cmd.Wait()
	if err != nil {
		slog.Error(fmt.Sprintf("error [%v]", err))
	}

	realm.Shell()

	realm.Reboot()
}

func enterChrootStage() error {
	newRoot := os.Getenv("GINIT_CHROOT")
	if newRoot == "" {
		return nil
	}

	entrypoint := os.Getenv("GINIT_ENTRYPOINT")
	if entrypoint == "" {
		return fmt.Errorf("missing GINIT_ENTRYPOINT")
	}

	if err := syscall.Chroot(newRoot); err != nil {
		return fmt.Errorf("chroot to %s: %w", newRoot, err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("change directory to new root: %w", err)
	}

	if err := syscall.Unmount("/proc", syscall.MNT_DETACH); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("unmount proc: %w", err)
	}

	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if port := os.Getenv("GINIT_VSOCK_PORT"); port != "" {
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
			return fmt.Errorf("disable guest entrypoint core dumps: %w", err)
		}
		if err := launchVSockService(port); err != nil {
			return err
		}
	}
	entries := splitQuotedFields(entrypoint)
	if len(entries) == 0 {
		return fmt.Errorf("empty entrypoint")
	}
	entrypoint = entries[0]
	args := append([]string{entrypoint}, entries[1:]...)

	return syscall.Exec(entrypoint, args, os.Environ())
}

func splitQuotedFields(input string) []string {
	quoted := false
	fields := strings.FieldsFunc(input, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
			return true
		}
		return !quoted && r == ' '
	})

	for i := range fields {
		fields[i] = strings.Trim(fields[i], "\"")
	}

	return fields
}

// CmdlinePath is the default location for the cmdline
const CmdlinePath = "/proc/cmdline"

// ParseCmdLine will read through the command line and return the source and destination
func ParseCmdLine(path string) (m map[string]string, err error) {
	// allow path override
	if path == "" {
		path = CmdlinePath
	}

	m = make(map[string]string)
	// Read the file
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	quoted := false
	a := strings.FieldsFunc(string(b), func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	for x := range a {
		kv := strings.Split(a[x], "=")
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return
}

func startTetragon() error {
	cmd := exec.Command("/usr/local/bin/tetragon", "--kernel", "6.1")
	//cmd.Stdout = os.Stdout
	err := cmd.Start()
	if err != nil {
		return err
	}

	fmt.Println(`                   [@@@@@@@@@@@@@@@@@@@@]                   
        @@@@@@@@@@========================@@@@@@@@@@        
        @@========================================@@        
        @@========================================@@        
        @@========================================@@        
        @@========================================@@        
        @@@@@@@@@@@@@@@@@@========@@@@@@@@@@@@@@@@@@        
                        @@========@@                        
        @@@@@@@@@@@@@@@ @@========@@ @@@@@@@@@@@@@@@        
        @@***********@@ @@========@@ @>>>>>>>>>>>>@@        
        @(***********@@ @@========@@ @>>>>>>>>>>>>]@        
        @[***********@@ @@========@@ @>>>>>>>>>>>>}@        
        @@@@@@@@@@@@@@@ @@========@@ @@@@@@@@@@@@@@@        
                        @@========@@                        
        @@%@@@@@@@@@@@@ @@========@@ @@@@@@@@@@@@@@@        
         @@==========@@ @@========@@ @(((((((((((@@         
         @@==========@@ @@========@{ @(((((((((((@@         
          @@=========@@ @@========@] @((((((((((@@          
           @@@@@@@@@@@@ @@========@  @@@@@@@@@@@@           
                        @@========@                         
             @@@@@@@@@@ @@========@  @@@@@@@@@@             
              @@)))))[@ @@========@  @<<<<<<@@              
                @@))))@ @@========@  @<<<<@@                
                  @@))@ @@========@  @<<@@                  
                    @@@ @@========@  @@@                    
                         @@======@@                         
                           @@@@@@         `)

	fmt.Println("Secured by Tetragon - https://tetragon.io")
	return nil
}
