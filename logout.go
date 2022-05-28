package hamr

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// logoutHandler maps to log out route
func (auth *auth) logoutHandler(ctx *gin.Context) {
	_, accessToken := getAccessTokenFromRequest(ctx)

	if err := auth.destroySession(accessToken); err != nil {
		ctx.JSON(http.StatusBadRequest, err.Error())
		return
	}
}
