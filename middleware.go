package hamr

import (
	"errors"
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
func (auth *auth) authorize(obj, act string, adapter *gormadapter.Adapter, w http.ResponseWriter, r *http.Request) (bool, error) {
	_, token := getAccessTokenFromRequest(w, r)
	if strings.TrimSpace(token) == "" {
		return false, errors.New("token not found")
	}

	claims, valid := auth.extractAccessTokenClaims(token)
	if claims == nil || !valid {
		return false, errors.New("invalid access token claims")
	}

	userIdFromRequestClaims := claims["sub"]
	accessTokenUuid := claims["uuid"]
	if userIdFromRequestClaims == nil || accessTokenUuid == nil {
		return false, errors.New("userId or accessTokenUuid is nil")
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		return false, errors.New(fmt.Sprintf("failed to get access token from cache: %s", err))
	}

	userIdFromCacheClaims, ok := accessTokenCached["sub"]
	if !ok {
		return false, errors.New("sub not found in accessTokenCached")
	}

	if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
		return false, errors.New("userIdFromRequestClaims does not match userIdFromCacheClaims")
	}

	if adapter != nil {
		id := strconv.Itoa(int(userIdFromRequestClaims.(float64)))

		// enforce Casbin policy
		if policyOk, policyErr := enforce(id, obj, act, adapter); policyErr != nil || !policyOk {
			return false, errors.New(fmt.Sprintf("casbin policy not passed, err: %s", policyErr))
		}
	}

	return true, nil
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
