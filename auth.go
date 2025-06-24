package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

type key int

// ACMETxtKey is a context key for ACMETxt struct
const ACMETxtKey key = 0

// AuthForRegister middleware for register request
func AuthForRegister(register httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		username, password, ok := r.BasicAuth()
		if !ok {
			WriteJsonResponse(w, http.StatusUnauthorized, jsonError("unauthorized"))
			return
		}
		pass, err := DB.GetAdminPassByUsername(username)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error while trying to get user")
			// To protect against timed side channel (never gonna give you up)
			correctPassword(password, "$2a$10$8JEFVNYYhLoBysjAxe2yBuXrkDojBQBkVpXEQgyQyjn43SvJ4vL36")
			WriteJsonResponse(w, http.StatusUnauthorized, jsonError("unauthorized"))
			return
		}
		if !correctPassword(password, pass) {
			WriteJsonResponse(w, http.StatusUnauthorized, jsonError("unauthorized"))
			return
		}
		register(w, r, p)
	}
}

// AuthForUpdate middleware for update request
func AuthForUpdate(update httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		postData := ACMETxt{}
		user, err := getUserFromRequest(r)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error while trying to get user")
			WriteJsonResponse(w, http.StatusUnauthorized, jsonError("unauthorized"))
			return
		}
		if !updateAllowedFromIP(r, user) {
			log.WithFields(log.Fields{"error": "ip_unauthorized"}).Error("Update not allowed from IP")
			WriteJsonResponse(w, http.StatusForbidden, jsonError("forbidden"))
			return
		}
		dec := json.NewDecoder(r.Body)
		err = dec.Decode(&postData)
		if err != nil {
			log.WithFields(log.Fields{"error": "json_error", "string": err.Error()}).Error("Decode error")
			WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_request"))
			return
		}
		if user.Subdomain != postData.Subdomain {
			log.WithFields(log.Fields{"error": "subdomain_mismatch", "name": postData.Subdomain, "expected": user.Subdomain}).Error("Subdomain mismatch")
			WriteJsonResponse(w, http.StatusForbidden, jsonError("forbidden"))
			return
		}
		// Set user info to the decoded ACMETxt object
		postData.Username = user.Username
		postData.Password = user.Password
		// Set the ACMETxt struct to context to pull in from update function
		ctx := context.WithValue(r.Context(), ACMETxtKey, postData)
		update(w, r.WithContext(ctx), p)
	}
}

func getUserFromRequest(r *http.Request) (ACMETxt, error) {
	uname := r.Header.Get("X-Api-User")
	passwd := r.Header.Get("X-Api-Key")
	username, err := getValidUsername(uname)
	if err != nil {
		return ACMETxt{}, fmt.Errorf("Invalid username: %s: %s", uname, err.Error())
	}
	if validKey(passwd) {
		dbuser, err := DB.GetByUsername(username)
		if err != nil {
			log.WithFields(log.Fields{"error": err.Error()}).Error("Error while trying to get user")
			// To protect against timed side channel (never gonna give you up)
			correctPassword(passwd, "$2a$10$8JEFVNYYhLoBysjAxe2yBuXrkDojBQBkVpXEQgyQyjn43SvJ4vL36")

			return ACMETxt{}, fmt.Errorf("Invalid username: %s", uname)
		}
		if correctPassword(passwd, dbuser.Password) {
			return dbuser, nil
		}
		return ACMETxt{}, fmt.Errorf("Invalid password for user %s", uname)
	}
	return ACMETxt{}, fmt.Errorf("Invalid key for user %s", uname)
}

func updateAllowedFromIP(r *http.Request, user ACMETxt) bool {
	if Config.API.UseHeader {
		ips := getIPListFromHeader(r.Header.Get(Config.API.HeaderName))
		return user.allowedFromList(ips)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error(), "remoteaddr": r.RemoteAddr}).Error("Error while parsing remote address")
		host = ""
	}
	return user.allowedFrom(host)
}
