package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

// RegResponse is a struct for registration response JSON
type RegResponse struct {
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	Fulldomain string   `json:"fulldomain"`
	Subdomain  string   `json:"subdomain"`
	Allowfrom  []string `json:"allowfrom"`
}

func webRegisterPost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var err error
	aTXT := ACMETxt{}
	bdata, _ := io.ReadAll(r.Body)
	if len(bdata) > 0 {
		err = json.Unmarshal(bdata, &aTXT)
		if err != nil {
			WriteJsonResponse(w, http.StatusBadRequest, jsonError("malformed_json_payload"))
			return
		}
	}

	// Fail with malformed CIDR mask in allowfrom
	err = aTXT.AllowFrom.isValid()
	if err != nil {
		WriteJsonResponse(w, http.StatusBadRequest, jsonError("invalid_allowfrom_cidr"))
		return
	}

	// Create new user
	var nu ACMETxt
	nu, err = DB.Register(aTXT.AllowFrom)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Error in registration")
		WriteJsonResponse(w, http.StatusInternalServerError, jsonError(fmt.Sprintf("%v", err)))
	}
	log.WithFields(log.Fields{"user": nu.Username.String()}).Debug("Created new user")
	regStruct := RegResponse{nu.Username.String(), nu.Password, nu.Subdomain + "." + Config.General.Domain, nu.Subdomain, nu.AllowFrom.ValidEntries()}
	var reg []byte
	reg, err = json.Marshal(regStruct)
	if err != nil {
		log.WithFields(log.Fields{"error": "json"}).Debug("Could not marshal JSON")
		WriteJsonResponse(w, http.StatusInternalServerError, jsonError("json_error"))
	}
	WriteJsonResponse(w, http.StatusCreated, reg)
}

func webUpdatePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Get user
	a, ok := r.Context().Value(ACMETxtKey).(ACMETxt)
	if !ok {
		log.WithFields(log.Fields{"error": "context"}).Error("Context error")
	}
	// NOTE: An invalid subdomain should not happen - the auth handler should
	// reject POSTs with an invalid subdomain before this handler. Reject any
	// invalid subdomains anyway as a matter of caution.
	if !validSubdomain(a.Subdomain) {
		log.WithFields(log.Fields{"error": "subdomain", "subdomain": a.Subdomain, "txt": a.Value}).Debug("Bad update data")
		WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_subdomain"))
		return
	}
	if a.Value == "" && len(a.AValues) < 1 && len(a.AAAAValues) < 1 {
		WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_txt"))
		return
	}
	if a.Value != "" && !validTXT(a.Value) {
		log.WithFields(log.Fields{"error": "txt", "subdomain": a.Subdomain, "txt": a.Value}).Debug("Bad update data")
		WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_txt"))
		return
	}
	for i := range a.AValues {
		var ip net.IP
		ip = net.ParseIP(a.AValues[i])
		if ip != nil {
			ip = ip.To4()
		}
		if ip == nil {
			log.WithFields(log.Fields{"error": "a", "subdomain": a.Subdomain, "a": a.AValues[i]}).Debug("Bad update data")
			WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_a"))
			return
		}
		a.AValues[i] = ip.String()
	}
	for i := range a.AAAAValues {
		var ip6 net.IP
		ip6 = net.ParseIP(a.AAAAValues[i])
		if ip6 == nil || ip6.To4() != nil {
			log.WithFields(log.Fields{"error": "aaaa", "subdomain": a.Subdomain, "aaaa": a.AAAAValues[i]}).Debug("Bad update data")
			WriteJsonResponse(w, http.StatusBadRequest, jsonError("bad_aaaa"))
			return
		}
		a.AAAAValues[i] = ip6.String()
	}
	err := DB.Update(a.ACMETxtPost)
	if err != nil {
		log.WithFields(log.Fields{"error": err.Error()}).Debug("Error while trying to update record")
		WriteJsonResponse(w, http.StatusInternalServerError, jsonError("db_error"))
		return
	}
	log.WithFields(log.Fields{"subdomain": a.Subdomain, "txt": a.Value}).Debug("TXT A AAAA updated")
	WriteJsonResponse(w, http.StatusOK, []byte("{\"txt\": \""+a.Value+"\", \"a\": \""+strings.Join(a.AValues, " ")+"\", \"aaaa\": \""+strings.Join(a.AAAAValues, " ")+"\"}"))
	return
}

func WriteJsonResponse(w http.ResponseWriter, statusCode int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

// Endpoint used to check the readiness and/or liveness (health) of the server.
func healthCheck(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
}
