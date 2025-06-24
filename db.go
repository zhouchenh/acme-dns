package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// DBVersion shows the database version this code uses. This is used for update checks.
var DBVersion = 1

var acmeTable = `
	CREATE TABLE IF NOT EXISTS acmedns(
		Name TEXT,
		Value TEXT
	);`

var adminTable = `
	CREATE TABLE IF NOT EXISTS admins(
        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
        Password TEXT NOT NULL,
    );`

var userTable = `
	CREATE TABLE IF NOT EXISTS records(
        Username TEXT UNIQUE NOT NULL PRIMARY KEY,
        Password TEXT NOT NULL,
        Subdomain TEXT UNIQUE NOT NULL,
		AllowFrom TEXT
    );`

var txtTable = `
    CREATE TABLE IF NOT EXISTS txt(
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

var txtTablePG = `
    CREATE TABLE IF NOT EXISTS txt(
		rowid SERIAL,
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL DEFAULT '',
		LastUpdate INT
	);`

var aTable = `
    CREATE TABLE IF NOT EXISTS a(
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL,
		LastUpdate INT
	);`

var aaaaTable = `
    CREATE TABLE IF NOT EXISTS aaaa(
		Subdomain TEXT NOT NULL,
		Value   TEXT NOT NULL,
		LastUpdate INT
	);`

// getSQLiteStmt replaces all PostgreSQL prepared statement placeholders (eg. $1, $2) with SQLite variant "?"
func getSQLiteStmt(s string) string {
	re, _ := regexp.Compile(`\$[0-9]`)
	return re.ReplaceAllString(s, "?")
}

func (d *acmedb) Init(engine string, connection string) error {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	db, err := sql.Open(engine, connection)
	if err != nil {
		return err
	}
	d.DB = db
	// Check version first to try to catch old versions without version string
	var versionString string
	_ = d.DB.QueryRow("SELECT Value FROM acmedns WHERE Name='db_version'").Scan(&versionString)
	if versionString == "" {
		versionString = "0"
	}
	_, _ = d.DB.Exec(acmeTable)
	_, _ = d.DB.Exec(adminTable)
	_, _ = d.DB.Exec(userTable)
	if Config.Database.Engine == "sqlite3" {
		_, _ = d.DB.Exec(txtTable)
	} else {
		_, _ = d.DB.Exec(txtTablePG)
	}
	_, _ = d.DB.Exec(aTable)
	_, _ = d.DB.Exec(aaaaTable)
	// If everything is fine, handle db upgrade tasks
	if err == nil {
		err = d.checkDBUpgrades(versionString)
	}
	if err == nil {
		if versionString == "0" {
			// No errors so we should now be in version 1
			insversion := fmt.Sprintf("INSERT INTO acmedns (Name, Value) values('db_version', '%d')", DBVersion)
			_, err = db.Exec(insversion)
		}
	}
	return err
}

func (d *acmedb) checkDBUpgrades(versionString string) error {
	var err error
	version, err := strconv.Atoi(versionString)
	if err != nil {
		return err
	}
	if version != DBVersion {
		return d.handleDBUpgrades(version)
	}
	return nil

}

func (d *acmedb) handleDBUpgrades(version int) error {
	if version == 0 {
		return d.handleDBUpgradeTo1()
	}
	return nil
}

func (d *acmedb) handleDBUpgradeTo1() error {
	var err error
	var subdomains []string
	rows, err := d.DB.Query("SELECT Subdomain FROM records")
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade")
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var subdomain string
		err = rows.Scan(&subdomain)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while reading values")
			return err
		}
		subdomains = append(subdomains, subdomain)
	}
	err = rows.Err()
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
		return err
	}
	tx, err := d.DB.Begin()
	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		_ = tx.Commit()
	}()
	_, _ = tx.Exec("DELETE FROM txt")
	for _, subdomain := range subdomains {
		if subdomain != "" {
			// Insert two rows for each subdomain to txt table
			err = d.NewTXTValuesInTransaction(tx, subdomain)
			if err != nil {
				log.WithFields(log.Fields{"error": err.Error()}).Error("Error in DB upgrade while inserting values")
				return err
			}
		}
	}
	// SQLite doesn't support dropping columns
	if Config.Database.Engine != "sqlite3" {
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS Value")
		_, _ = tx.Exec("ALTER TABLE records DROP COLUMN IF EXISTS LastActive")
	}
	_, err = tx.Exec("UPDATE acmedns SET Value='1' WHERE Name='db_version'")
	return err
}

// Create two rows for subdomain to the txt table
func (d *acmedb) NewTXTValuesInTransaction(tx *sql.Tx, subdomain string) error {
	var err error
	instr := fmt.Sprintf("INSERT INTO txt (Subdomain, LastUpdate) values('%s', 0)", subdomain)
	_, _ = tx.Exec(instr)
	_, _ = tx.Exec(instr)
	return err
}

func (d *acmedb) Register(afrom cidrslice) (ACMETxt, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	var err error
	tx, err := d.DB.Begin()
	// Rollback if errored, commit if not
	defer func() {
		if err != nil {
			_ = tx.Rollback()
			return
		}
		_ = tx.Commit()
	}()
	a := newACMETxt()
	a.AllowFrom = cidrslice(afrom.ValidEntries())
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(a.Password), 10)
	regSQL := `
    INSERT INTO records(
        Username,
        Password,
        Subdomain,
		AllowFrom) 
        values($1, $2, $3, $4)`
	if Config.Database.Engine == "sqlite3" {
		regSQL = getSQLiteStmt(regSQL)
	}
	sm, err := tx.Prepare(regSQL)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Database error in prepare")
		return a, errors.New("SQL error")
	}
	defer sm.Close()
	_, err = sm.Exec(a.Username.String(), passwordHash, a.Subdomain, a.AllowFrom.JSON())
	if err == nil {
		err = d.NewTXTValuesInTransaction(tx, a.Subdomain)
	}
	return a, err
}

func (d *acmedb) GetAdminPassByUsername(username string) (string, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	var results []string
	getSQL := `
	SELECT Password
	FROM admins
	WHERE Username=$1 LIMIT 1
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return "", err
	}
	defer sm.Close()
	rows, err := sm.Query(username)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	// It will only be one row though
	for rows.Next() {
		var result string
		err = rows.Scan(&result)
		if err != nil {
			return "", err
		}
		results = append(results, result)
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return "", errors.New("admin not found")
}

func (d *acmedb) GetByUsername(u uuid.UUID) (ACMETxt, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	var results []ACMETxt
	getSQL := `
	SELECT Username, Password, Subdomain, AllowFrom
	FROM records
	WHERE Username=$1 LIMIT 1
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return ACMETxt{}, err
	}
	defer sm.Close()
	rows, err := sm.Query(u.String())
	if err != nil {
		return ACMETxt{}, err
	}
	defer rows.Close()

	// It will only be one row though
	for rows.Next() {
		txt, err := getModelFromRow(rows)
		if err != nil {
			return ACMETxt{}, err
		}
		results = append(results, txt)
	}
	if len(results) > 0 {
		return results[0], nil
	}
	return ACMETxt{}, errors.New("no user")
}

func (d *acmedb) GetTXTForDomain(domain string) ([]string, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	domain = sanitizeString(domain)
	var txts []string
	getSQL := `
	SELECT Value FROM txt WHERE Subdomain=$1 LIMIT 2
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return txts, err
	}
	defer sm.Close()
	rows, err := sm.Query(domain)
	if err != nil {
		return txts, err
	}
	defer rows.Close()

	for rows.Next() {
		var rtxt string
		err = rows.Scan(&rtxt)
		if err != nil {
			return txts, err
		}
		txts = append(txts, rtxt)
	}
	return txts, nil
}

func (d *acmedb) GetAForDomain(domain string) ([]net.IP, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	domain = sanitizeString(domain)
	var ips []net.IP
	getSQL := `
	SELECT Value FROM a WHERE Subdomain=$1 LIMIT 255
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return ips, err
	}
	defer sm.Close()
	rows, err := sm.Query(domain)
	if err != nil {
		return ips, err
	}
	defer rows.Close()

	for rows.Next() {
		var ra string
		var ip net.IP
		err = rows.Scan(&ra)
		if err != nil {
			return ips, err
		}
		ip = net.ParseIP(ra)
		if ip != nil {
			ip = ip.To4()
		}
		if ip == nil {
			return ips, fmt.Errorf("invalid IPv4 address: %s", ra)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (d *acmedb) GetAAAAForDomain(domain string) ([]net.IP, error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	domain = sanitizeString(domain)
	var ip6s []net.IP
	getSQL := `
	SELECT Value FROM aaaa WHERE Subdomain=$1 LIMIT 255
	`
	if Config.Database.Engine == "sqlite3" {
		getSQL = getSQLiteStmt(getSQL)
	}

	sm, err := d.DB.Prepare(getSQL)
	if err != nil {
		return ip6s, err
	}
	defer sm.Close()
	rows, err := sm.Query(domain)
	if err != nil {
		return ip6s, err
	}
	defer rows.Close()

	for rows.Next() {
		var raaaa string
		var ip6 net.IP
		err = rows.Scan(&raaaa)
		if err != nil {
			return ip6s, err
		}
		ip6 = net.ParseIP(raaaa)
		if ip6 == nil {
			return ip6s, fmt.Errorf("invalid IPv6 address: %s", raaaa)
		}
		ip6s = append(ip6s, ip6)
	}
	return ip6s, nil
}

func (d *acmedb) CountRecords(domain string) (count int, err error) {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	domain = sanitizeString(domain)
	countTXTSQL := `
	SELECT COUNT(*) FROM txt WHERE Subdomain=$1 AND Value != ''
	`
	countASQL := `
	SELECT COUNT(*) FROM a WHERE Subdomain=$1
	`
	countAAAASQL := `
	SELECT COUNT(*) FROM aaaa WHERE Subdomain=$1
	`
	if Config.Database.Engine == "sqlite3" {
		countTXTSQL = getSQLiteStmt(countTXTSQL)
		countASQL = getSQLiteStmt(countASQL)
		countAAAASQL = getSQLiteStmt(countAAAASQL)
	}

	var countTXTStmt *sql.Stmt
	countTXTStmt, err = d.DB.Prepare(countTXTSQL)
	if err != nil {
		return
	}
	defer countTXTStmt.Close()

	var countAStmt *sql.Stmt
	countAStmt, err = d.DB.Prepare(countASQL)
	if err != nil {
		return
	}
	defer countAStmt.Close()

	var countAAAAStmt *sql.Stmt
	countAAAAStmt, err = d.DB.Prepare(countAAAASQL)
	if err != nil {
		return
	}
	defer countAAAAStmt.Close()

	var countTXTRows *sql.Rows
	countTXTRows, err = countTXTStmt.Query(domain)
	if err != nil {
		return
	}
	defer countTXTRows.Close()
	for countTXTRows.Next() {
		var c int
		err = countTXTRows.Scan(&c)
		if err != nil {
			return
		}
		count += c
	}

	var countARows *sql.Rows
	countARows, err = countAStmt.Query(domain)
	if err != nil {
		return
	}
	defer countARows.Close()
	for countARows.Next() {
		var c int
		err = countARows.Scan(&c)
		if err != nil {
			return
		}
		count += c
	}

	var countAAAARows *sql.Rows
	countAAAARows, err = countAAAAStmt.Query(domain)
	if err != nil {
		return
	}
	defer countAAAARows.Close()
	for countAAAARows.Next() {
		var c int
		err = countAAAARows.Scan(&c)
		if err != nil {
			return
		}
		count += c
	}

	return
}

func (d *acmedb) Update(a ACMETxtPost) error {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	var err error
	// Data in a is already sanitized
	timenow := time.Now().Unix()

	if a.Value != "" {
		updSQL := `
	UPDATE txt SET Value=$1, LastUpdate=$2
	WHERE rowid=(
		SELECT rowid FROM txt WHERE Subdomain=$3 ORDER BY LastUpdate LIMIT 1)
	`
		if Config.Database.Engine == "sqlite3" {
			updSQL = getSQLiteStmt(updSQL)
		}

		var sm *sql.Stmt
		sm, err = d.DB.Prepare(updSQL)
		if err != nil {
			return err
		}
		defer sm.Close()
		_, err = sm.Exec(a.Value, timenow, a.Subdomain)
		if err != nil {
			return err
		}
	}

	if len(a.AValues) > 0 {
		deleteSQL := `
	DELETE FROM a
	WHERE Subdomain=$1
	`
		insertSQL := `
	INSERT INTO a(
        Subdomain,
        Value,
        LastUpdate) 
        values($1, $2, $3)
	`
		if Config.Database.Engine == "sqlite3" {
			deleteSQL = getSQLiteStmt(deleteSQL)
			insertSQL = getSQLiteStmt(insertSQL)
		}

		var deleteStmt *sql.Stmt
		deleteStmt, err = d.DB.Prepare(deleteSQL)
		if err != nil {
			return err
		}
		defer deleteStmt.Close()
		var insertStmt *sql.Stmt
		insertStmt, err = d.DB.Prepare(insertSQL)
		if err != nil {
			return err
		}
		defer insertStmt.Close()
		_, err = deleteStmt.Exec(a.Subdomain)
		if err != nil {
			return err
		}
		for i := range a.AValues {
			_, err = insertStmt.Exec(a.Subdomain, a.AValues[i], timenow)
			if err != nil {
				return err
			}
		}
	}

	if len(a.AAAAValues) > 0 {
		deleteSQL := `
	DELETE FROM aaaa
	WHERE Subdomain=$1
	`
		insertSQL := `
	INSERT INTO aaaa(
        Subdomain,
        Value,
        LastUpdate) 
        values($1, $2, $3)
	`
		if Config.Database.Engine == "sqlite3" {
			deleteSQL = getSQLiteStmt(deleteSQL)
			insertSQL = getSQLiteStmt(insertSQL)
		}

		var deleteStmt *sql.Stmt
		deleteStmt, err = d.DB.Prepare(deleteSQL)
		if err != nil {
			return err
		}
		defer deleteStmt.Close()
		var insertStmt *sql.Stmt
		insertStmt, err = d.DB.Prepare(insertSQL)
		if err != nil {
			return err
		}
		defer insertStmt.Close()
		_, err = deleteStmt.Exec(a.Subdomain)
		if err != nil {
			return err
		}
		for i := range a.AAAAValues {
			_, err = insertStmt.Exec(a.Subdomain, a.AAAAValues[i], timenow)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getModelFromRow(r *sql.Rows) (ACMETxt, error) {
	txt := ACMETxt{}
	afrom := ""
	err := r.Scan(
		&txt.Username,
		&txt.Password,
		&txt.Subdomain,
		&afrom)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("Row scan error")
	}

	cslice := cidrslice{}
	err = json.Unmarshal([]byte(afrom), &cslice)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Error("JSON unmarshall error")
	}
	txt.AllowFrom = cslice
	return txt, err
}

func (d *acmedb) Close() {
	d.DB.Close()
}

func (d *acmedb) GetBackend() *sql.DB {
	return d.DB
}

func (d *acmedb) SetBackend(backend *sql.DB) {
	d.DB = backend
}
