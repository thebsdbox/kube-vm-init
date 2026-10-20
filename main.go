package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/thebsdbox/ginit/pkg/realm"
)

func main() {
	if err := enterChrootStage(); err != nil {
		log.Fatalf("chroot stage error: %v", err)
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
		log.Errorf("Error mounting dev: [%v]", err)
	}

	// Create all devices
	err = d.CreateDevice()
	if err != nil {
		log.Errorf("Error creating device: [%v]", err)
	}

	// Mount any additional mounts
	err = m.MountAll()
	if err != nil {
		log.Errorf("Error mounting: [%v]", err)
	}

	// HERE IS WHERE THE MAIN CODE GOES
	log.Infoln("Starting ginit")
	//time.Sleep(time.Second * 2)

	//	log.Infoln("Beginning provisioning process")

	mac, err := realm.GetMAC()
	if err != nil {
		log.Errorln(err)
		//realm.Shell()
	}
	log.Infof("eth0 mac %s", mac)

	stuffs, err := ParseCmdLine(CmdlinePath)
	if err != nil {
		log.Errorln(err)
	}

	if stuffs["dhcp"] == "true" {
		log.Println("Starting DHCP client")
		go realm.DHCPClient()
	}

	err = startTetragon()
	if err != nil {
		log.Errorf("Tetragon error: [%v]", err)
	}

	_, err = realm.MountRootVolume(stuffs["newroot"])
	if err != nil {
		log.Errorf("Disk Error: [%v]", err)
	}

	if stuffs["hostname"] != "" {
		log.Infof("Setting hostname to %s", stuffs["hostname"])
		err = realm.SetHostname(stuffs["hostname"])
		if err != nil {
			log.Errorf("Error setting hostname: [%v]", err)
		}
	}

	if stuffs["dns"] != "" {
		log.Infof("Setting DNS to %s", stuffs["dns"])
		err = realm.SetDNS(stuffs["dns"])
		if err != nil {
			log.Errorf("Error setting DNS: [%v]", err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		log.Errorf("unable to resolve current executable: [%v]", err)
		realm.Shell()
		realm.Reboot()
	}

	cmd := exec.Command(self)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		"GINIT_CHROOT=/mnt",
		fmt.Sprintf("GINIT_ENTRYPOINT=%s", stuffs["entrypoint"]),
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
			log.Infoln("Restarting")
			realm.Reboot()
		}
		fmt.Println(s.String()) // ... do something ...|||
	}()
	err = cmd.Start()
	if err != nil {
		log.Errorf("command error [%v]", err)
	}
	err = cmd.Wait()
	if err != nil {
		log.Errorf("error [%v]", err)
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

	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("mark mounts private: %w", err)
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
