package main

import (
	"C"
	"encoding/json"
	"log"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"code.cloudfoundry.org/rfc5424"
	"github.com/allanhung/fluent-bit-out-syslog/pkg/syslog"
	"github.com/fluent/fluent-bit-go/output"
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	return output.FLBPluginRegister(
		def,
		"syslog",
		"syslog output plugin that follows RFC 5424",
	)
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	addr := output.FLBPluginConfigKey(plugin, "addr")
	name := output.FLBPluginConfigKey(plugin, "instancename")
	namespace := output.FLBPluginConfigKey(plugin, "namespace")
	cluster := output.FLBPluginConfigKey(plugin, "cluster")
	clusterid := output.FLBPluginConfigKey(plugin, "clusterid")
	tls := output.FLBPluginConfigKey(plugin, "tlsconfig")
	severityStr := output.FLBPluginConfigKey(plugin, "severity")
	facilityStr := output.FLBPluginConfigKey(plugin, "facility")
	taglabel := output.FLBPluginConfigKey(plugin, "taglabel")
	logformat := output.FLBPluginConfigKey(plugin, "logformat")
	kubernetesMeta := output.FLBPluginConfigKey(plugin, "kubernetesmeta")
	sanitizeHost := output.FLBPluginConfigKey(plugin, "sanitizehost")

	if addr == "" {
		log.Println("[out_syslog] ERROR: Addr is required")
		return output.FLB_ERROR
	}
	if name == "" {
		log.Println("[out_syslog] ERROR: InstanceName is required")
		return output.FLB_ERROR
	}

	var (
		sinks        []*syslog.Sink
		clusterSinks []*syslog.Sink
	)

	sink := &syslog.Sink{
		Addr:      addr,
		Name:      name,
		Namespace: namespace,
	}
	if tls != "" {
		var tlsConfig syslog.TLS
		err := json.Unmarshal([]byte(tls), &tlsConfig)
		if err != nil {
			log.Printf("[out_syslog] ERROR: Unable to unmarshal TLS config: %s", err)
			return output.FLB_ERROR
		}
		sink.TLS = &tlsConfig
	}
	if strings.ToLower(cluster) == "true" {
		clusterSinks = append(clusterSinks, sink)
	} else {
		sinks = append(sinks, sink)
	}

	if clusterid == "" {
		clusterid = "kubernetes"
	}

	if taglabel == "" {
		taglabel = "CONTAINER_NAME"
	}

	if logformat == "" {
		logformat = "RFC5424"
	}
	var priority int
	switch strings.ToUpper(logformat) {
	case "RFC3164":
		priority = int(decodeFacility3164(severityStr, facilityStr))
	default:
		priority = int(decodeFacility(severityStr, facilityStr))
	}
	k8smeta := true
	if len(kubernetesMeta) != 0 {
		var err error
		k8smeta, err = strconv.ParseBool(kubernetesMeta)
		if err != nil {
			log.Printf("[out_syslog] ERROR: Unable to parse KubernetesMeta: %s", err)
			return output.FLB_ERROR
		}
	}

	// Defaults to true so that plugin conforms better with rfc5424#section-6.2.4
	sanitize := true
	if len(sanitizeHost) != 0 {
		var err error
		sanitize, err = strconv.ParseBool(sanitizeHost)
		if err != nil {
			log.Printf("[out_syslog] ERROR: Unable to parse SanitizeHost: %s", err)
			return output.FLB_ERROR
		}
	}
	out := syslog.NewOut(
		sinks,
		clusterSinks,
		priority,
		clusterid,
		taglabel,
		logformat,
		k8smeta,
		syslog.WithSanitizeHost(sanitize),
	)

	// We are using runtime.KeepAlive to tell the Go Runtime to keep the
	// reference to this pointer because once it leaves this context and
	// enters cgo it will no longer be in scope of Go. If a GC event occurs
	// the memory is reclaimed.
	// NOTE 1: Yes we are passing the `out` pointer even though it points to a
	// struct that contains other Go pointers and this violates the rules as
	// defined here: https://golang.org/cmd/cgo/#hdr-Passing_pointers
	// > Go code may pass a Go pointer to C provided the Go memory to which it
	//   points does not contain any Go pointers.
	// But this seems to be the most stable solution even when comparing the
	// instance slice/index solution.
	// NOTE 2: Since we are asking the Go Runtime to not clean this memory
	// up, it can be a cause for a "memory leak" however we are not planning
	// on millions of sinks to be initialized.
	output.FLBPluginSetContext(plugin, unsafe.Pointer(out))
	runtime.KeepAlive(out)
	if strings.ToLower(cluster) == "true" {
		log.Printf("[out_syslog] Initializing plugin %s for cluster to destination %s", name, addr)
	} else {
		log.Printf("[out_syslog] Initializing plugin %s for namespace %s to destination %s", name, namespace, addr)
	}
	log.Printf("[out_syslog] severity=%s, facility=%s, taglabe=%s, logformat=%s, kubernetes meta=%v", severityStr, facilityStr, taglabel, logformat, k8smeta)
	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	var (
		ret    int
		ts     interface{}
		record map[interface{}]interface{}
	)

	out := (*syslog.Out)(ctx)

	dec := output.NewDecoder(data, int(length))
	for {
		ret, ts, record = output.GetRecord(dec)
		if ret != 0 {
			break
		}

		var timestamp time.Time
		switch tts := ts.(type) {
		case output.FLBTime:
			timestamp = tts.Time
		case uint64:
			// From our observation, when ts is of type uint64 it appears to
			// be the amount of seconds since unix epoch.
			timestamp = time.Unix(int64(tts), 0)
		default:
			timestamp = time.Now()
		}

		out.Write(record, timestamp, C.GoString(tag))
	}

	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	// TODO: We should probably call conn.Close() for each sink connection
	return output.FLB_OK
}

func main() {
}

func decodeFacility(severityString, facilityString string) rfc5424.Priority {
	var faciliryNum rfc5424.Priority
	var severityNum rfc5424.Priority

	switch strings.ToUpper(facilityString) {
	case "KERN":
		faciliryNum = rfc5424.Kern
	case "USER":
		faciliryNum = rfc5424.User
	case "MAIL":
		faciliryNum = rfc5424.Mail
	case "DAEMON":
		faciliryNum = rfc5424.Daemon
	case "AUTH":
		faciliryNum = rfc5424.Auth
	case "SYSLOG":
		faciliryNum = rfc5424.Syslog
	case "LPR":
		faciliryNum = rfc5424.Lpr
	case "NEWS":
		faciliryNum = rfc5424.News
	case "UUCP":
		faciliryNum = rfc5424.Uucp
	case "CRON":
		faciliryNum = rfc5424.Cron
	case "AUTHPRIV":
		faciliryNum = rfc5424.Authpriv
	case "FTP":
		faciliryNum = rfc5424.Ftp
	case "LOCAL0":
		faciliryNum = rfc5424.Local0
	case "LOCAL1":
		faciliryNum = rfc5424.Local1
	case "LOCAL2":
		faciliryNum = rfc5424.Local2
	case "LOCAL3":
		faciliryNum = rfc5424.Local3
	case "LOCAL4":
		faciliryNum = rfc5424.Local4
	case "LOCAL5":
		faciliryNum = rfc5424.Local5
	case "LOCAL6":
		faciliryNum = rfc5424.Local6
	case "LOCAL7":
		faciliryNum = rfc5424.Local7
	default:
		log.Printf("[out_syslog] Facility %s not found. Use default facility rfc5424.User", strings.ToUpper(facilityString))
		faciliryNum = rfc5424.User
	}
	switch strings.ToUpper(severityString) {
	case "EMERGENCY":
		return rfc5424.Emergency
	case "ALERT":
		return rfc5424.Alert
	case "CRIT":
		return rfc5424.Crit
	case "ERROR":
		return rfc5424.Error
	case "WARNING":
		return rfc5424.Warning
	case "NOTICE":
		return rfc5424.Notice
	case "INFO":
		return rfc5424.Info
	case "DEBUG":
		return rfc5424.Debug
	default:
		log.Printf("[out_syslog] Severity %s not found. Use default severity rfc5424.Info", strings.ToUpper(severityString))
		severityNum = rfc5424.Info
	}
	return severityNum + faciliryNum
}

func decodeFacility3164(severityString, facilityString string) syslog.Priority {
	var faciliryNum syslog.Priority
	var severityNum syslog.Priority

	switch strings.ToUpper(facilityString) {
	case "KERN":
		faciliryNum = syslog.Kern
	case "USER":
		faciliryNum = syslog.User
	case "MAIL":
		faciliryNum = syslog.Mail
	case "DAEMON":
		faciliryNum = syslog.Daemon
	case "AUTH":
		faciliryNum = syslog.Auth
	case "SYSLOG":
		faciliryNum = syslog.Syslog
	case "LPR":
		faciliryNum = syslog.Lpr
	case "NEWS":
		faciliryNum = syslog.News
	case "UUCP":
		faciliryNum = syslog.Uucp
	case "CRON":
		faciliryNum = syslog.Cron
	case "AUTHPRIV":
		faciliryNum = syslog.Authpriv
	case "FTP":
		faciliryNum = syslog.Ftp
	case "LOCAL0":
		faciliryNum = syslog.Local0
	case "LOCAL1":
		faciliryNum = syslog.Local1
	case "LOCAL2":
		faciliryNum = syslog.Local2
	case "LOCAL3":
		faciliryNum = syslog.Local3
	case "LOCAL4":
		faciliryNum = syslog.Local4
	case "LOCAL5":
		faciliryNum = syslog.Local5
	case "LOCAL6":
		faciliryNum = syslog.Local6
	case "LOCAL7":
		faciliryNum = syslog.Local7
	default:
		log.Printf("[out_syslog] Facility %s not found. Use default facility rfc3164.User", strings.ToUpper(facilityString))
		faciliryNum = syslog.User
	}

	switch strings.ToUpper(severityString) {
	case "EMERGENCY":
		return syslog.Emergency
	case "ALERT":
		return syslog.Alert
	case "CRIT":
		return syslog.Crit
	case "ERROR":
		return syslog.Error
	case "WARNING":
		return syslog.Warning
	case "NOTICE":
		return syslog.Notice
	case "INFO":
		return syslog.Info
	case "DEBUG":
		return syslog.Debug
	default:
		log.Printf("[out_syslog] Severity %s not found. Use default severity rfc3164.Info", strings.ToUpper(severityString))
		severityNum = syslog.Info
	}
	return severityNum + faciliryNum
}
