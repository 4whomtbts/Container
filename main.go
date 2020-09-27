package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

func ioctl(fd , flag, data uintptr) error {
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, flag, data); err != 0 {
		return err
	}
	return nil
}

func mount(source, target, fstype string, flags uintptr, data string) error {
	return syscall.Mount(source, target, fstype, flags, data)
}

func ptsname(f *os.File) (string, error) {
	var n int
	if err := ioctl(f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		return "", err
	}
	return fmt.Sprintf("/dev/pts/%d", n), nil
}

func unlockpt(f *os.File) error {
	var u int
	return ioctl(f.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&u)))
}

func clone(flags uintptr) (int, error) {
	syscall.ForkLock.Lock()
	pid, _, err := syscall.RawSyscall(syscall.SYS_CLONE, flags, 0, 0)
	syscall.ForkLock.Unlock()
	if err != 0 {
		return -1, err
	}
	return int(pid), nil
}

func closefd(fd uintptr) error {
	return syscall.Close(int(fd))
}

func closeMasterAndStd(master *os.File) error {
	closefd(master.Fd())
	closefd(0)
	closefd(1)
	closefd(2)
	return nil
}

func openTerminal(name string, flag int) (*os.File, error) {
	r, e := syscall.Open(name, flag, 0)
	if e != nil {
		return nil, &os.PathError{"open", name, e}
	}
	return os.NewFile(uintptr(r), name), nil
}

func dup2(fd1, fd2 uintptr) error {
	return syscall.Dup2(int(fd1), int(fd2))
}

func dupSlave(slave *os.File) error {
	if slave.Fd() != 0 {
		return fmt.Errorf("slave fd not 0 %d", slave.Fd())
	}
	if err := dup2(slave.Fd(), 1); err != nil {
		return err
	}
	if err := dup2(slave.Fd(), 2); err != nil {
		return err
	}
	return nil
}

/*
func exec(cmd string, args []string, env []string) error {
	return syscall.Exec(cmd, args, env)
}
 */

func WaitOnPid(pid int) (exitcode int, err error) {
	child, err := os.FindProcess(pid)
	if err != nil {
		return -1, err
	}
	state, err := child.Wait()
	if err != nil {
		return -1, err
	}
	return state.ExitCode(), nil
}

func setsid() (int, error) {
	return syscall.Setsid()
}

func setctty() error {
	if _, _, err := syscall.RawSyscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCSCTTY), 0); err != 0 {
		return err
	}
	return nil
}

func parentDeathSignal() error {
	if _, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0, 0); err != 0 {
		return err
	}
	return nil
}

func setgroups(gids []int) error {
	return syscall.Setgroups(gids)
}

func setresuid(rgid, egid, sgid int) error {
	return syscall.Setresgid(rgid, egid, sgid)
}

func setresgid(rgid, egid, sgid int) error {
	return syscall.Setresgid(rgid, egid, sgid)
}

func setupUser() error {
	if err := setgroups(nil); err != nil {
		return err
	}
	if err := setresgid(0, 0, 0); err != nil {
		return err
	}
	if err := setresuid(0, 0, 0); err != nil {
		return err
	}
	return nil
}
func sethostname(name string) error {
	return syscall.Sethostname([]byte(name))
}

func exec(cmd string, args []string, env []string) error {
	return syscall.Exec(cmd, args, env)
}

func SetupNewMountNamespace(rootfs, console string, readonly bool) error {
	return nil
}

func main() {
	rootfs, err := filepath.EvalSymlinks("/root/cont")
	if err != nil {
		println("ERR = ", err.Error())
		return
	}
	println("ans = ", rootfs)
	l, err := os.Stat(rootfs)
	if err != nil {
		println("stat ERR = ", err)
		return
	}
	println(l.Name(),", ",l.IsDir(),", ",l.Mode())


	// createMasterAndConsole
	master, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR | syscall.O_NOCTTY | syscall.O_CLOEXEC, 0)
	if err != nil {
		println("ptmx err = ", err)
	}
	println(master.Fd(), ",",master.Name())

	console, err := ptsname(master)
	if err != nil {
		println("ptsname err = ", err)
	}
	println("Console = ", console)

	if err := unlockpt(master); err != nil {
		println("unlockpt fail = ", err)
		return
	}
	///////////////////////////////
	logger, err := os.OpenFile("/root/logs", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0755)
	if err != nil {
		println("logger ERR = ", err)
	}
	log.SetOutput(logger)

	flag := syscall.CLONE_VFORK | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS

	pid, err := clone(uintptr(flag | 0x14));
	if err != nil {
		println("clone err = ", err)
	}

	if pid == 0 {
		println("This is newnamespace of child process")
		if err := closeMasterAndStd(master); err != nil {
			println("closeMasterAndStd ERR = ", err)
		}
		slave, err := openTerminal(console, syscall.O_RDWR)
		if err != nil {
			println("open terminal err = ", err)
		}
		if err := dupSlave(slave); err != nil {
			println("dupSlave ERR = ", err)
		}

		if _, err := setsid(); err != nil {
			println("setsid ERR = ", err)
		}

		if err := setctty(); err != nil {
			println("setctty ERR = ", err)
		}

		if err := parentDeathSignal(); err != nil {
			println("parent death ERR = ", err)
		}

		if err := sethostname("foo"); err != nil {
			println("sethostname ERR = ", err)
		}
		if err := setupUser(); err != nil {
			println("setup user ERR = ", err)
		}

		if err := mount("/root/proc", "/proc", "proc",
						syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_RELATIME, ""); err != nil {
			println("mount error= ", err)
			return
		}

		if err := exec("/bin/bash", nil, []string {
			"HOME=/",
			"PATH=PATH=$PATH:/bin:/usr/bin:/sbin:/usr/sbin",
			"container=docker",
			"TERM=xterm",
		}); err != nil {
			println("exec ERR = ", err)
		}
	} else {
		println("pid가 ", pid)

		go func() {
			if _, err := io.Copy(os.Stdout, master); err != nil {
				log.Println(err)
			}
		}()

		go func() {
			if _, err := io.Copy(master, os.Stdin); err != nil {
				log.Println(err)
			}
		}()
		exit, err := WaitOnPid(pid)
		if err != nil {
			println("waitonpid fail = ", err.Error(), ", ", exit)
		}
	}
	/*
	var n int
	if err := ioctl(master.Fd(), TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {

	}
	 */
	//

}
