package main

import (
	"database/sql"
	"net"
	"sync"

	"github.com/google/uuid"
)

// Config is global configuration struct
var Config DNSConfig

// DB is used to access the database functions in acme-dns
var DB database

// DNSConfig holds the config structure
type DNSConfig struct {
	General   general
	Database  dbsettings
	API       httpapi
	Logconfig logconfig
}

// Config file general section
type general struct {
	Listen        string
	Proto         string `toml:"protocol"`
	Domain        string
	Nsname        string
	Nsadmin       string
	Debug         bool
	StaticRecords []string `toml:"records"`
}

type dbsettings struct {
	Engine     string
	Connection string
}

// API config
type httpapi struct {
	Domain              string `toml:"api_domain"`
	IP                  string
	DisableRegistration bool   `toml:"disable_registration"`
	AutocertPort        string `toml:"autocert_port"`
	Port                string `toml:"port"`
	TLS                 string
	TLSCertPrivkey      string `toml:"tls_cert_privkey"`
	TLSCertFullchain    string `toml:"tls_cert_fullchain"`
	ACMECacheDir        string `toml:"acme_cache_dir"`
	NotificationEmail   string `toml:"notification_email"`
	CorsOrigins         []string
	UseHeader           bool   `toml:"use_header"`
	HeaderName          string `toml:"header_name"`
}

// Logging config
type logconfig struct {
	Level   string `toml:"loglevel"`
	Logtype string `toml:"logtype"`
	File    string `toml:"logfile"`
	Format  string `toml:"logformat"`
}

type acmedb struct {
	Mutex sync.Mutex
	DB    *sql.DB
}

type database interface {
	Init(string, string) error
	Register(cidrslice) (ACMETxt, error)
	GetAdminPassByUsername(string) (string, error)
	GetByUsername(uuid.UUID) (ACMETxt, error)
	GetTXTForDomain(string) ([]string, error)
	GetAForDomain(string) ([]net.IP, error)
	GetAAAAForDomain(string) ([]net.IP, error)
	CountRecords(string) (int, error)
	Update(ACMETxtPost) error
	GetBackend() *sql.DB
	SetBackend(*sql.DB)
	Close()
}
