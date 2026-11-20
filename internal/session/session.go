// Package session names the network, the date, and the person viewing Sitrep.
package session

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

var dbusSockets = []string{"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"}

var notADomain = map[string]struct{}{
	"": {}, ".": {}, "local": {}, "localdomain": {}, "localhost": {},
}

// View is the /api/session document.
type View struct {
	Domain string `json:"domain"`
	Date   string `json:"date"`
	User   string `json:"user"`
}

// For builds the header identity from the request and the host.
func For(header http.Header) View {
	return View{Domain: networkName(), Date: viewDate(), User: viewerName(header)}
}

func viewDate() string {
	now := time.Now()
	months := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	return fmt.Sprintf("%s %d, %d", months[now.Month()-1], now.Day(), now.Year())
}

func oneLine(value string, limit int) string {
	text := strings.Join(strings.Fields(value), " ")
	for _, ch := range text {
		if ch < 32 {
			return ""
		}
	}
	if text == "" {
		return ""
	}
	if len(text) > limit {
		return text[:limit]
	}
	return text
}

func oneUser(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	for _, ch := range text {
		if ch <= 32 || ch == '/' || ch == '\\' {
			return ""
		}
	}
	if len(text) > 64 {
		return text[:64]
	}
	return text
}

func viewerName(header http.Header) string {
	for _, key := range []string{"Remote-User", "X-Forwarded-User"} {
		if found := oneUser(header.Get(key)); found != "" {
			return found
		}
	}
	if found := seatUser(); found != "" {
		return found
	}
	for _, key := range []string{"CHECKLIST_USER", "SUDO_USER", "USER", "LOGNAME"} {
		found := oneUser(os.Getenv(key))
		if found != "" && found != "root" {
			return found
		}
	}
	current, err := user.Current()
	if err == nil {
		if found := oneUser(current.Username); found != "" && found != "root" {
			return found
		}
	}
	return ""
}

func seatUser() string {
	raw, err := os.ReadFile("/run/systemd/seats/seat0")
	if err != nil {
		return ""
	}
	uid := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ACTIVE_UID=") {
			uid = strings.TrimSpace(strings.TrimPrefix(line, "ACTIVE_UID="))
		}
	}
	if uid == "" || strings.Trim(uid, "0123456789") != "" {
		return ""
	}
	record, err := os.ReadFile("/run/systemd/users/" + uid)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(record), "\n") {
		if strings.HasPrefix(line, "NAME=") {
			return oneUser(strings.TrimPrefix(line, "NAME="))
		}
	}
	return ""
}

func networkName() string {
	if chosen := oneLine(os.Getenv("CHECKLIST_DOMAIN"), 80); chosen != "" {
		return chosen
	}
	domain, name := "", ""
	if facts, err := connectionFacts(); err == nil {
		domain, name = facts[0], facts[1]
	}
	if domain != "" {
		first := strings.TrimRight(strings.Fields(domain)[0], ".")
		if strings.Contains(first, ".") && !isIgnoredDomain(first) {
			return first
		}
	}
	if found := oneLine(resolvDomain(), 80); found != "" {
		return found
	}
	if name != "" {
		return name
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	if host != "" && !isIgnoredDomain(host) {
		return host
	}
	return "This network"
}

func isIgnoredDomain(name string) bool {
	_, ok := notADomain[strings.ToLower(name)]
	return ok
}

func resolvDomain() string {
	var names []string
	for _, path := range []string{"/etc/resolv.conf", "/run/NetworkManager/resolv.conf"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && (parts[0] == "domain" || parts[0] == "search") {
				names = append(names, parts[1:]...)
			}
		}
	}
	for _, name := range names {
		domain := strings.TrimRight(strings.TrimSpace(name), ".")
		if strings.Contains(domain, ".") && !isIgnoredDomain(domain) {
			return domain
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	if strings.Contains(host, ".") {
		suffix := strings.TrimRight(host[strings.Index(host, ".")+1:], ".")
		if strings.Contains(suffix, ".") && !isIgnoredDomain(suffix) {
			return suffix
		}
	}
	return ""
}

func connectionFacts() ([2]string, error) {
	bus, err := dialBus()
	if err != nil {
		return [2]string{}, err
	}
	defer bus.close()
	path, err := bus.get("/org/freedesktop/NetworkManager", "org.freedesktop.NetworkManager", "PrimaryConnection")
	if err != nil {
		return [2]string{}, err
	}
	object, _ := path.(string)
	if object == "" || object == "/" {
		return [2]string{}, nil
	}
	id, err := bus.get(object, "org.freedesktop.NetworkManager.Connection.Active", "Id")
	if err != nil {
		return [2]string{}, err
	}
	name, _ := id.(string)
	domain := ""
	dhcp, err := bus.get(object, "org.freedesktop.NetworkManager.Connection.Active", "Dhcp4Config")
	if err == nil {
		if dhcpPath, ok := dhcp.(string); ok && dhcpPath != "" && dhcpPath != "/" {
			options, err := bus.get(dhcpPath, "org.freedesktop.NetworkManager.DHCP4Config", "Options")
			if err == nil {
				if table, ok := options.(map[string]string); ok {
					domain = table["domain_name"]
					if domain == "" {
						domain = table["domain_search"]
					}
				}
			}
		}
	}
	return [2]string{oneLine(domain, 80), oneLine(name, 80)}, nil
}

type bus struct {
	conn    net.Conn
	pending []byte
	serial  uint32
}

func dialBus() (*bus, error) {
	var last error
	for _, path := range dbusSockets {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			last = err
			continue
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		token := hex.EncodeToString([]byte(strconv.Itoa(os.Getuid())))
		if _, err := conn.Write(append([]byte("\x00AUTH EXTERNAL " + token + "\r\n"))); err != nil {
			conn.Close()
			last = err
			continue
		}
		buf := make([]byte, 0, 256)
		tmp := make([]byte, 256)
		for !strings.Contains(string(buf), "\r\n") {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				conn.Close()
				last = err
				buf = nil
				break
			}
		}
		if buf == nil {
			continue
		}
		line, rest, _ := strings.Cut(string(buf), "\r\n")
		if !strings.HasPrefix(line, "OK") {
			conn.Close()
			last = fmt.Errorf("%s", line)
			continue
		}
		if _, err := conn.Write([]byte("BEGIN\r\n")); err != nil {
			conn.Close()
			return nil, err
		}
		client := &bus{conn: conn, pending: []byte(rest)}
		if _, _, err := client.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", nil); err != nil {
			conn.Close()
			last = err
			continue
		}
		return client, nil
	}
	if last == nil {
		last = fmt.Errorf("system bus is not available")
	}
	return nil, last
}

func (b *bus) close() { b.conn.Close() }

func (b *bus) get(path, iface, name string) (any, error) {
	body, offset, err := b.call("org.freedesktop.NetworkManager", path, "org.freedesktop.DBus.Properties", "Get", "ss", []string{iface, name})
	if err != nil {
		return nil, err
	}
	return variantValue(body, offset)
}

func (b *bus) call(destination, path, iface, member, signature string, args []string) ([]byte, int, error) {
	b.serial++
	message := dbusMessage(b.serial, destination, path, iface, member, signature, args)
	b.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := b.conn.Write(message); err != nil {
		return nil, 0, err
	}
	for {
		kind, body, offset, pending, err := dbusRead(b.conn, b.pending)
		if err != nil {
			return nil, 0, err
		}
		b.pending = pending
		if kind == 3 {
			return nil, 0, fmt.Errorf("system bus call failed")
		}
		if kind == 2 {
			return body, offset, nil
		}
	}
}

func dbusMessage(serial uint32, destination, path, iface, member, signature string, args []string) []byte {
	type part struct {
		code byte
		kind string
		val  string
	}
	parts := []part{
		{1, "o", path},
		{6, "s", destination},
		{2, "s", iface},
		{3, "s", member},
	}
	if signature != "" {
		parts = append(parts, part{8, "g", signature})
	}
	var fields []byte
	for _, item := range parts {
		fields = pad(fields, 8)
		fields = append(fields, item.code)
		fields = packSignature(fields, item.kind)
		if item.kind == "g" {
			fields = packSignature(fields, item.val)
		} else {
			fields = packString(fields, item.val)
		}
	}
	var body []byte
	for _, arg := range args {
		body = packString(body, arg)
	}
	message := []byte{'l', 1, 0, 1}
	message = append(message, putUint32(uint32(len(body)))...)
	message = append(message, putUint32(serial)...)
	message = append(message, putUint32(uint32(len(fields)))...)
	message = append(message, fields...)
	message = pad(message, 8)
	return append(message, body...)
}

func pad(buf []byte, alignment int) []byte {
	for len(buf)%alignment != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func packString(buf []byte, text string) []byte {
	buf = pad(buf, 4)
	raw := []byte(text)
	buf = append(buf, putUint32(uint32(len(raw)))...)
	buf = append(buf, raw...)
	return append(buf, 0)
}

func packSignature(buf []byte, signature string) []byte {
	raw := []byte(signature)
	buf = append(buf, byte(len(raw)))
	buf = append(buf, raw...)
	return append(buf, 0)
}

func putUint32(n uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], n)
	return raw[:]
}

func dbusRead(conn net.Conn, pending []byte) (byte, []byte, int, []byte, error) {
	head, pending, err := recvExact(conn, 16, pending)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	bodyLen := binary.LittleEndian.Uint32(head[4:8])
	fieldsLen := binary.LittleEndian.Uint32(head[12:16])
	_, pending, err = recvExact(conn, int(fieldsLen), pending)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	padLen := (8 - ((16 + int(fieldsLen)) % 8)) % 8
	if padLen > 0 {
		_, pending, err = recvExact(conn, padLen, pending)
		if err != nil {
			return 0, nil, 0, nil, err
		}
	}
	body, pending, err := recvExact(conn, int(bodyLen), pending)
	if err != nil {
		return 0, nil, 0, nil, err
	}
	return head[1], body, 16 + int(fieldsLen) + padLen, pending, nil
}

func recvExact(conn net.Conn, n int, pending []byte) ([]byte, []byte, error) {
	buf := append([]byte{}, pending...)
	tmp := make([]byte, 4096)
	for len(buf) < n {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		got, err := conn.Read(tmp)
		if got > 0 {
			buf = append(buf, tmp[:got]...)
		}
		if err != nil && len(buf) < n {
			return nil, nil, err
		}
		if err != nil {
			break
		}
	}
	if len(buf) < n {
		return nil, nil, fmt.Errorf("system bus closed")
	}
	return buf[:n], buf[n:], nil
}

func variantValue(body []byte, offset int) (any, error) {
	blob := make([]byte, offset+len(body))
	copy(blob[offset:], body)
	sig, i, err := readSignature(blob, offset)
	if err != nil {
		return nil, err
	}
	switch sig {
	case "s", "o":
		text, _, err := readString(blob, i)
		return text, err
	case "a{sv}":
		return readStringDict(blob, i)
	default:
		return "", nil
	}
}

func align(offset, n int) int { return (offset + n - 1) & ^(n - 1) }

func readSignature(blob []byte, offset int) (string, int, error) {
	if offset >= len(blob) {
		return "", 0, fmt.Errorf("short signature")
	}
	length := int(blob[offset])
	offset++
	if offset+length+1 > len(blob) {
		return "", 0, fmt.Errorf("short signature")
	}
	sig := string(blob[offset : offset+length])
	return sig, offset + length + 1, nil
}

func readString(blob []byte, offset int) (string, int, error) {
	offset = align(offset, 4)
	if offset+4 > len(blob) {
		return "", 0, fmt.Errorf("short string")
	}
	length := int(binary.LittleEndian.Uint32(blob[offset:]))
	offset += 4
	if offset+length+1 > len(blob) {
		return "", 0, fmt.Errorf("short string")
	}
	return string(blob[offset : offset+length]), offset + length + 1, nil
}

func readStringDict(blob []byte, offset int) (map[string]string, error) {
	offset = align(offset, 4)
	if offset+4 > len(blob) {
		return nil, fmt.Errorf("short dict")
	}
	nbytes := int(binary.LittleEndian.Uint32(blob[offset:]))
	offset += 4
	offset = align(offset, 8)
	end := offset + nbytes
	found := map[string]string{}
	for offset+8 <= end && offset < len(blob) {
		offset = align(offset, 8)
		key, next, err := readString(blob, offset)
		if err != nil {
			return found, nil
		}
		sig, next, err := readSignature(blob, next)
		if err != nil || sig != "s" {
			return found, nil
		}
		value, next, err := readString(blob, next)
		if err != nil {
			return found, nil
		}
		found[key] = value
		offset = next
	}
	return found, nil
}
