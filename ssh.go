package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/shlex"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %q", t))
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func(channel ssh.Channel, requests <-chan *ssh.Request) {
		s := session{channel: channel}
		for req := range requests {
			if err := s.request(req); err != nil {
				errmsg := []byte(err.Error())
				// Append a trailing newline; the error message is
				// displayed as-is by ssh(1).
				if errmsg[len(errmsg)-1] != '\n' {
					errmsg = append(errmsg, '\n')
				}
				req.Reply(false, errmsg)
				channel.Write(errmsg)
				channel.Close()
			}
		}
	}(channel, requests)
}

type session struct {
	env     []string
	ptyf    *os.File
	ttyf    *os.File
	channel ssh.Channel
}

func stringFromPayload(payload []byte, offset int) (string, int, error) {
	if got, want := len(payload), offset+4; got < want {
		return "", 0, fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
	}
	namelen := binary.BigEndian.Uint32(payload[offset : offset+4])
	if got, want := len(payload), offset+4+int(namelen); got < want {
		return "", 0, fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
	}
	name := payload[offset+4 : offset+4+int(namelen)]
	return string(name), offset + 4 + int(namelen), nil
}

func (s *session) request(req *ssh.Request) error {
	switch req.Type {
	case "pty-req":
		var err error
		s.ptyf, s.ttyf, err = pty.Open()
		if err != nil {
			return err
		}
		_, next, err := stringFromPayload(req.Payload, 0)
		if err != nil {
			return err
		}
		if got, want := len(req.Payload), next+4+4; got < want {
			return fmt.Errorf("request payload too short: got %d, want >= %d", got, want)
		}

		w, h := parseDims(req.Payload[next:])
		SetWinsize(s.ptyf.Fd(), w, h)
		// Responding true (OK) here will let the client
		// know we have a pty ready for input
		req.Reply(true, nil)

	case "window-change":
		w, h := parseDims(req.Payload)
		SetWinsize(s.ptyf.Fd(), w, h)

	case "env":
		name, next, err := stringFromPayload(req.Payload, 0)
		if err != nil {
			return err
		}

		value, _, err := stringFromPayload(req.Payload, next)
		if err != nil {
			return err
		}

		s.env = append(s.env, fmt.Sprintf("%s=%s", name, value))

	case "shell":
		// as per https://tools.ietf.org/html/rfc4254#section-6.5,
		// shell requests don’t carry a payload, and we don’t have a
		// default shell, so decline the request
		return fmt.Errorf("shell requests unsupported, use exec")

	case "exec":
		if got, want := len(req.Payload), 4; got < want {
			return fmt.Errorf("exec request payload too short: got %d, want >= %d", got, want)
		}

		cmdline, err := shlex.Split(string(req.Payload[4:]))
		if err != nil {
			return err
		}

		if cmdline[0] == "scp" {
			return scpSink(s.channel, req, cmdline)
		}

		cmd := exec.Command(cmdline[0], cmdline[1:]...)
		cmd.Env = s.env
		cmd.SysProcAttr = &syscall.SysProcAttr{}

		if s.ttyf == nil {
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return err
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				return err
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return err
			}
			cmd.SysProcAttr.Setsid = true

			if err := cmd.Start(); err != nil {
				return err
			}

			req.Reply(true, nil)

			go io.Copy(s.channel, stdout)
			go io.Copy(s.channel.Stderr(), stderr)
			go func() {
				io.Copy(stdin, s.channel)
				stdin.Close()
			}()

			if err := cmd.Wait(); err != nil {
				return err
			}

			s.channel.Close()
			return nil
		}

		defer func() {
			s.ttyf.Close()
			s.ttyf = nil
		}()

		cmd.Stdout = s.ttyf
		cmd.Stdin = s.ttyf
		cmd.Stderr = s.ttyf
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Setsid = true

		if err := cmd.Start(); err != nil {
			s.ptyf.Close()
			s.ptyf = nil
			return err
		}

		close := func() {
			s.channel.Close()
			cmd.Process.Wait()
		}

		// pipe session to cmd and vice-versa
		var once sync.Once
		go func() {
			io.Copy(s.channel, s.ptyf)
			once.Do(close)
		}()
		go func() {
			io.Copy(s.ptyf, s.channel)
			once.Do(close)
		}()

		req.Reply(true, nil)

	default:
		return fmt.Errorf("unknown request type: %q", req.Type)
	}

	return nil
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}