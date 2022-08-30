package hamr

import (
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"net/http"
	"strconv"
)

// authorize middleware will check if request is authorized.
// If adapter is passed Casbin policy will be checked as well
func (auth *auth) authorize(obj, act string, adapter *gormadapter.Adapter, w http.ResponseWriter, r *http.Request) error {
	claims, err := auth.getClaimsFromRequest(w, r)
	if err != nil {
		return err
	}

	userIdFromRequestClaims := claims["sub"]
	accessTokenUuid := claims["uuid"]
	if userIdFromRequestClaims == nil || accessTokenUuid == nil {
		return errors.New("userId or accessTokenUuid is nil")
	}

	accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
	if err != nil {
		return errors.New(fmt.Sprintf("failed to get access token from cache: %s", err))
	}

	userIdFromCacheClaims, ok := accessTokenCached["sub"]
	if !ok {
		return errors.New("sub not found in accessTokenCached")
	}

	if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
		return errors.New("userIdFromRequestClaims does not match userIdFromCacheClaims")
	}

	if adapter != nil {
		id := strconv.Itoa(int(userIdFromRequestClaims.(float64)))

		// enforce Casbin policy
		if policyOk, policyErr := enforce(id, obj, act, auth.conf.CasbinPolicy, adapter); policyErr != nil || !policyOk {
			return errors.New(fmt.Sprintf("casbin policy not passed, err: %s", policyErr))
		}
	}

	return nil
}

// enforce Casbin policy
func enforce(sub string, obj string, act string, policy string, adapter *gormadapter.Adapter) (bool, error) {
	m, err := model.NewModelFromString(policy)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin model from string: %s", err)
	}

	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return false, fmt.Errorf("failed to create casbin enforcer: %s", err)
	}

	err = enforcer.LoadPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to load casbin policy from database: %s", err)
	}

	return enforcer.Enforce(sub, obj, act)
}
