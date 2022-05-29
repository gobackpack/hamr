package hamr

import (
	"net/http"
)

/*
Logout module.
*/

// logoutHandler maps to log out route
func (auth *auth) logoutHandler(w http.ResponseWriter, r *http.Request) {
	_, accessToken := getAccessTokenFromRequest(w, r)

	if err := auth.destroySession(accessToken); err != nil {
		JSON(http.StatusBadRequest, w, err.Error())
		return
	}
}
