package authn

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/go-convenience/stringsx"
	"github.com/ory/herodot"
	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
)

type AuthenticatorHawkConfiguration struct {
	CheckRequestURL string `json:"check_request_url"`
	ExtraFrom       string `json:"extra_from"`
	SubjectFrom     string `json:"subject_from"`
}

type AuthenticatorHawk struct {
	c configuration.Provider
}

func NewAuthenticatorHawk(c configuration.Provider) *AuthenticatorHawk {
	return &AuthenticatorHawk{
		c: c,
	}
}

func (a *AuthenticatorHawk) GetID() string {
	return "hawk"
}

func (a *AuthenticatorHawk) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorHawk) Config(config json.RawMessage) (*AuthenticatorHawkConfiguration, error) {
	var c AuthenticatorHawkConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	if len(c.ExtraFrom) == 0 {
		c.ExtraFrom = "extra"
	}

	if len(c.SubjectFrom) == 0 {
		c.SubjectFrom = "subject"
	}

	return &c, nil
}

func (a *AuthenticatorHawk) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	if !hawkResponsible(r) {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body, err := forwardRequestToAuthenticator(r, cf.CheckRequestURL)
	if err != nil {
		return err
	}

	var (
		subject string
		extra   map[string]interface{}

		subjectRaw = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.SubjectFrom).Raw, "null"))
		extraRaw   = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.ExtraFrom).Raw, "null"))
	)

	if err = json.Unmarshal(subjectRaw, &subject); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured subject_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.SubjectFrom, body, subjectRaw).WithTrace(err)
	}

	if err = json.Unmarshal(extraRaw, &extra); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured extra_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.ExtraFrom, body, extraRaw).WithTrace(err)
	}

	session.Subject = subject
	session.Extra = extra
	return nil
}

func hawkResponsible(r *http.Request) bool {
	token := r.Header.Get("Authorization")
	split := strings.Split(token, " ")

	return len(split) >= 2 && strings.EqualFold(split[0], "hawk")
}

func forwardRequestToAuthenticator(r *http.Request, checkRequestURL string) (json.RawMessage, error) {
	port := r.URL.Port()
	if port == "" {
		if r.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	values := map[string]string{
		"method":        r.Method,
		"url":           r.URL.RequestURI(),
		"host":          r.URL.Hostname(),
		"port":          port,
		"authorization": r.Header.Get("Authorization"),
		"contentType":   r.Header.Get("Content-Type"),
	}

	jsonValue, _ := json.Marshal(values)

	res, err := http.Post(checkRequestURL, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, helper.ErrForbidden.WithReason(err.Error()).WithTrace(err)
	}

	if res.StatusCode == 200 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return json.RawMessage{}, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch hawk context from remote: %+v", err))
		}
		return body, nil
	} else {
		return json.RawMessage{}, errors.WithStack(helper.ErrUnauthorized)
	}
}
