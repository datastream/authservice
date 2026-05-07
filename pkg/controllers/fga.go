// Package controllers provides HTTP handlers for the OAuth service using the Gin framework.
// It includes controllers for login, OAuth authorization, token management, and FGA integration.
package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/datastream/authservice/pkg/core"
	"github.com/gin-gonic/gin"
	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

// FGAController handles FGA (Fine-Grained Authorization) operations.
type FGAController struct {
	FgaClient            *client.OpenFgaClient
	AuthorizationModelId string
	// Add fields as necessary
}

// Constants for FGA relations and objects.
const (
	relAccess      = "access"
	relOwner       = "owner"
	objAuthService = "resource:authservice"
	objModelFmt    = "model:%s"
)

// abort logs an error (if any) and aborts the Gin request with a JSON error payload.
func (fga *FGAController) abort(c *gin.Context, status int, msg string, err error) {
	if err != nil {
		log.Printf("%s: %v", msg, err)
	} else {
		log.Println(msg)
	}
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}

// permissionMiddleware returns a Gin middleware that checks an FGA permission.
// rel is the relation (e.g., "access" or "owner").
// objTemplate may contain a "%s" placeholder that will be filled from the URL param "id".
func (fga *FGAController) permissionMiddleware(rel, objTemplate string) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := c.GetString("Subject")
		if subject == "" {
			fga.abort(c, http.StatusUnauthorized, "Missing authentication subject", nil)
			return
		}
		obj := objTemplate
		if strings.Contains(objTemplate, "%s") {
			id := c.Param("id")
			if id == "" {
				fga.abort(c, http.StatusBadRequest, "model ID missing in URL", nil)
				return
			}
			obj = fmt.Sprintf(objTemplate, id)
		}
		allowed, err := fga.checkPermission(c.Request.Context(), subject, rel, obj)
		if err != nil {
			fga.abort(c, http.StatusInternalServerError, "FGA check error", err)
			return
		}
		if !allowed {
			fga.abort(c, http.StatusForbidden, "Forbidden", nil)
			return
		}
		c.Next()
	}
}

// NewFGAController creates a new FGAController from configuration.
func NewFGAController(config core.OpenFgaConfig) (*FGAController, error) {
	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:               config.URL,     // required, e.g. https://api.fga.example
		StoreId:              config.StoreID, // optional, not needed for `CreateStore` and `ListStores`, required before calling for all other methods
		AuthorizationModelId: config.ModelID, // optional, can be overridden per request
		Credentials: &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{
				ApiToken: config.Token, // will be passed as the "Authorization: Bearer ${ApiToken}" request header
			},
		},
	})
	if err != nil {
		log.Println("init fga failed", err, config.URL)
		return nil, err
	}
	return &FGAController{FgaClient: fgaClient, AuthorizationModelId: config.ModelID}, nil
}

// checkPermission is a small helper to centralize FGA Check calls.
func (fga *FGAController) checkPermission(ctx context.Context, user, relation, object string) (bool, error) {
	payload := client.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}
	options := client.ClientCheckOptions{
		AuthorizationModelId: &fga.AuthorizationModelId,
	}
	response, err := fga.FgaClient.Check(ctx).Body(payload).Options(options).Execute()
	if err != nil {
		return false, err
	}
	return response.GetAllowed(), nil
}

// FGAMiddleware checks if the current user has "access" relation to the auth service.
// Deprecated: Use PermissionMiddleware with rel="access" and objTemplate="resource:authservice" instead.
func (fga *FGAController) FGAMiddleware() gin.HandlerFunc {
	return fga.permissionMiddleware(relAccess, objAuthService)
}

// FGASepMiddleware checks if the current user has "owner" relation to a specific model.
// Deprecated: Use PermissionMiddleware with rel="owner" and objTemplate="model:%s" instead.
func (fga *FGAController) FGASepMiddleware() gin.HandlerFunc {
	return fga.permissionMiddleware(relOwner, objModelFmt)
}

// create models
func (fga *FGAController) Models(c *gin.Context) {
	var body client.ClientWriteAuthorizationModelRequest
	err := c.Bind(&body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	data, err := fga.FgaClient.WriteAuthorizationModel(c.Request.Context()).Body(body).Execute()
	if err != nil {
		log.Println("FGA create model error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	// create tuple in authorization model owner
	options := client.ClientWriteOptions{
		AuthorizationModelId: &fga.AuthorizationModelId,
	}
	bodyTupe := client.ClientWriteRequest{
		Writes: []client.ClientTupleKey{
			{
				Object:   fmt.Sprintf("model:%s", data.AuthorizationModelId),
				Relation: "owner",
				User:     c.GetString("Subject"),
			},
		},
	}
	_, err = fga.FgaClient.Write(c.Request.Context()).Body(bodyTupe).Options(options).Execute()
	if err != nil {
		log.Println("FGA create model owner tuple error:", err, data.AuthorizationModelId)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error, failed to create owner tuple"})
		return
	}
	c.JSON(http.StatusOK, data)
}

// show models
func (fga *FGAController) GetModel(c *gin.Context) {
	modelID := c.Param("id")
	err := fga.FgaClient.SetAuthorizationModelId(modelID)
	if err != nil {
		log.Println("FGA set model id error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	fgaModels, err := fga.FgaClient.ReadAuthorizationModels(c.Request.Context()).Execute()
	if err != nil {
		log.Println("FGA get models error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, fgaModels)
}

// evaluate permissions
func (fga *FGAController) Evaluate(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientCheckRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientCheckOptions{
		AuthorizationModelId: &modeID,
	}
	data, err := fga.FgaClient.Check(c.Request.Context()).
		Body(body).
		Options(options).
		Execute()
	if err != nil {
		log.Println("FGA evaluate error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	if !data.HasAllowed() {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
		return
	}
	c.JSON(http.StatusOK, data)
}

// manage tuples
func (fga *FGAController) Tuples(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientWriteRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientWriteOptions{
		AuthorizationModelId: &modeID,
	}
	_, err := fga.FgaClient.Write(c.Request.Context()).Body(body).Options(options).Execute()
	if err != nil {
		log.Println("FGA create tuples error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "tuples created"})
}

// delete tuples
func (fga *FGAController) DeleteTuples(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientWriteRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientWriteOptions{
		AuthorizationModelId: openfga.PtrString(modeID),
	}
	data, err := fga.FgaClient.Write(c.Request.Context()).
		Body(body).
		Options(options).
		Execute()
	if err != nil {
		log.Println("FGA delete tuples error:", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(http.StatusOK, data)
}
