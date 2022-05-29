package hamr

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
)

// authorize middleware will check if request is authorized.
// If adapter is passed Casbin policy will be checked as well
// TODO: removing Gin dependency in progress
func (auth *auth) authorize(
	obj, act string,
	adapter *gormadapter.Adapter,
	w http.ResponseWriter,
	r *http.Request,
	next http.HandlerFunc) {

	_, token := getAccessTokenFromRequest(w, r)
	if strings.TrimSpace(token) == "" {
		logrus.Error("token not found")
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	claims, valid := auth.extractAccessTokenClaims(token)
	if claims == nil || !valid {
		logrus.Error("invalid access token claims, valid: ", valid)
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	userIdFromRequestClaims := claims["sub"]
	accessTokenUuid := claims["uuid"]
	if userIdFromRequestClaims == nil || accessTokenUuid == nil {
		logrus.Error("userId or accessTokenUuid is nil")
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		logrus.Error("failed to get access token from cache: ", err)
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	userIdFromCacheClaims, ok := accessTokenCached["sub"]
	if !ok {
		logrus.Error("sub not found in accessTokenCached")
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
		logrus.Error("userIdFromRequestClaims does not match userIdFromCacheClaims")
		JSON(http.StatusUnauthorized, w, "")
		return
	}

	if adapter != nil {
		id := strconv.Itoa(int(userIdFromRequestClaims.(float64)))

		// enforce Casbin policy
		if policyOk, policyErr := enforce(id, obj, act, adapter); policyErr != nil || !policyOk {
			logrus.Error("casbin policy not passed, err: ", policyErr)
			JSON(http.StatusUnauthorized, w, "")
			return
		}
	}

	next(w, r)
}

// enforce Casbin policy
func enforce(sub string, obj string, act string, adapter *gormadapter.Adapter) (bool, error) {
	enforcer, err := casbin.NewEnforcer(*Path+"casbin_model.conf", adapter)
	if err != nil {
		logrus.Error("failed to create casbin enforcer: ", err)
		return false, fmt.Errorf("failed to create casbin enforcer: %s", err)
	}

	err = enforcer.LoadPolicy()
	if err != nil {
		logrus.Error("failed to load casbin policy from database: ", err)
		return false, fmt.Errorf("failed to load casbin policy from database: %s", err)
	}

	return enforcer.Enforce(sub, obj, act)
}
