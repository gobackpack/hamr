package hamr

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
)

// authorize middleware will check if request is authorized.
// If adapter is passed Casbin policy will be checked as well
func (auth *auth) authorize(obj, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		_, token := getAccessTokenFromRequest(ctx)
		if strings.TrimSpace(token) == "" {
			logrus.Error("token not found")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, valid := auth.extractAccessTokenClaims(token)
		if claims == nil || !valid {
			logrus.Error("invalid access token claims, valid: ", valid)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userIdFromRequestClaims := claims["sub"]
		accessTokenUuid := claims["uuid"]
		if userIdFromRequestClaims == nil || accessTokenUuid == nil {
			logrus.Error("userId or accessTokenUuid is nil")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		accessTokenCached, err := auth.getTokenFromCache(accessTokenUuid.(string))
		if err != nil {
			logrus.Error("failed to get access token from cache: ", err)
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userIdFromCacheClaims, ok := accessTokenCached["sub"]
		if !ok {
			logrus.Error("sub not found in accessTokenCached")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if userIdFromRequestClaims.(float64) != userIdFromCacheClaims.(float64) {
			logrus.Error("userIdFromRequestClaims does not match userIdFromCacheClaims")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if adapter != nil {
			id := strconv.Itoa(int(userIdFromRequestClaims.(float64)))

			// enforce Casbin policy
			if policyOk, policyErr := enforce(id, obj, act, adapter); policyErr != nil || !policyOk {
				logrus.Error("casbin policy not passed, err: ", policyErr)
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}

		ctx.Next()
	}
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
