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
func (svc *service) authorize(obj, act string, adapter *gormadapter.Adapter) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, _ := getAccessTokenFromRequest(ctx)
		if strings.TrimSpace(token) == "" {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, valid := svc.extractAccessTokenClaims(token)
		if claims == nil || !valid {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userId := claims["sub"]
		accessTokenUuid := claims["uuid"]
		if userId == nil || accessTokenUuid == nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		bUserId, err := svc.cache.Get(fmt.Sprint(accessTokenUuid))
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if fmt.Sprint(userId) != string(bUserId) {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if adapter != nil {
			id := strconv.Itoa(int(userId.(float64)))

			// enforce Casbin policy
			if ok, policyErr := enforce(id, obj, act, adapter); policyErr != nil || !ok {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}

		ctx.Next()
	}
}

// getAccessTokenFromRequest will extract access token from request's Authorization headers
func getAccessTokenFromRequest(ctx *gin.Context) (string, string) {
	authHeader := strings.Split(ctx.GetHeader("Authorization"), " ")
	if len(authHeader) != 2 {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return "", ""
	}

	schema, token := authHeader[0], authHeader[1]
	if schema != "Bearer" {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return "", ""
	}

	return token, schema
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
