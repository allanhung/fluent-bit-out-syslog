package syslog

const severityMask = 0x07
const facilityMask = 0xf8

type Priority int

const (
	Emergency Priority = iota
	Alert
	Crit
	Error
	Warning
	Notice
	Info
	Debug
)

const (
	Kern Priority = iota << 3
	User
	Mail
	Daemon
	Auth
	Syslog
	Lpr
	News
	Uucp
  	Cron
	Authpriv
  	Ftp
  	Ntp
  	LogAudit
  	LogAlert
  	Clock
	Local0
	Local1
	Local2
	Local3
	Local4
	Local5
	Local6
	Local7
)
