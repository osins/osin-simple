package util

import (
	"fmt"
	"net/url"
	"strings"
)

// error returned when validation don't match
type UriValidationError string

func (e UriValidationError) Error() string {
	return string(e)
}

func newUriValidationError(msg string, base string, redirect string) UriValidationError {
	return UriValidationError(fmt.Sprintf("%s: %s / %s", msg, base, redirect))
}

// Parse urls, resolving uri references to base url
func ParseUrls(baseUrl, redirectUrl string) (retBaseUrl, retRedirectUrl *url.URL, err error) {
	var base, redirect *url.URL
	// parse base url
	if base, err = url.Parse(baseUrl); err != nil {
		return nil, nil, err
	}

	// parse redirect url
	if redirect, err = url.Parse(redirectUrl); err != nil {
		return nil, nil, err
	}

	// must not have fragment
	if base.Fragment != "" || redirect.Fragment != "" {
		return nil, nil, newUriValidationError("url must not include fragment.", baseUrl, redirectUrl)
	}

	// Scheme must match
	if redirect.Scheme != base.Scheme {
		return nil, nil, newUriValidationError("scheme mismatch", baseUrl, redirectUrl)
	}

	// Host must match
	if redirect.Host != base.Host {
		return nil, nil, newUriValidationError("host mismatch", baseUrl, redirectUrl)
	}

	// resolve references to base url
	retBaseUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: base.Path})
	retRedirectUrl = (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/"}).ResolveReference(&url.URL{Path: redirect.Path, RawQuery: redirect.RawQuery})
	return
}

// ValidateUriList validates that redirectUri is contained in baseUriList.
// baseUriList may be a string separated by separator.
// If separator is blank, validate only 1 URI.
func ValidateRedirectUriList(baseUriList string, redirectUri string, separator string) (realRedirectUri string, err error) {
	if separator == "" {
		return ValidateUri(baseUriList, redirectUri)
	}

	uris := strings.Split(baseUriList, separator)
	for _, s := range uris {
		fmt.Printf("\nbase: %v, redirect: %v\n", s, redirectUri)
		if r, err := ValidateUri(s, redirectUri); err == nil {
			return r, nil
		}
	}

	return "", fmt.Errorf("redirect uri error.")
}

// ValidateUri validates that redirectUri is contained in baseUri
func ValidateUri(baseUri string, redirectUri string) (realRedirectUri string, err error) {
	var base, redirect *url.URL
	if base, err = url.Parse(baseUri); err != nil {
		return "", fmt.Errorf("redirect url error")
	}

	if redirect, err = url.Parse(redirectUri); err != nil {
		return "", fmt.Errorf("redirect url error")
	}

	if base.Host != redirect.Host {
		return "", fmt.Errorf("redirect url error")
	}

	if base.Path != redirect.Path {
		return "", fmt.Errorf("redirect url error")
	}

	baseValues, err := url.ParseQuery(base.RawQuery)
	if err != nil {
		return "", fmt.Errorf("redirect url error")
	}

	redirectValues, err := url.ParseQuery(base.RawQuery)
	if err != nil {
		return "", fmt.Errorf("redirect url error")
	}

	for k := range baseValues {
		if _, ok := redirectValues[k]; !ok {
			return "", fmt.Errorf("redirect url error")
		}
	}

	return redirect.String(), nil
}

// Returns the first uri from an uri list
func FirstUri(baseUriList string, separator string) string {
	if separator != "" {
		slist := strings.Split(baseUriList, separator)
		if len(slist) > 0 {
			return slist[0]
		}
	} else {
		return baseUriList
	}

	return ""
}
