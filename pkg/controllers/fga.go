package controllers

import (
	"context"
	"fmt"
	"log"

	"github.com/datastream/authservice/pkg/core"
	"github.com/gin-gonic/gin"
	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

type FGAController struct {
	FgaClient            *client.OpenFgaClient
	AuthorizationModelId string
	// Add fields as necessary
}

func NewFGAController(config core.OpenFgaConfig) (*FGAController, error) {
	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl:               config.URL,     // required, e.g. https://api.fga.example
		StoreId:              config.StoreID, // optional, not needed for \`CreateStore\` and \`ListStores\`, required before calling for all other methods
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
func (fga *FGAController) FGAMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user information from the context (e.g., from JWT or session)
		subject := c.GetString("Subject")
		allowed, err := fga.checkPermission(context.Background(), subject, "access", "resource:authservice")
		if err != nil {
			log.Println("FGA check error:", err)
			c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.Next()
	}
}
func (fga *FGAController) FGASepMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user information from the context (e.g., from JWT or session)
		subject := c.GetString("Subject")
		modeID := c.Param("id")
		allowed, err := fga.checkPermission(context.Background(), subject, "owner", fmt.Sprintf("model:%s", modeID))
		if err != nil {
			log.Println("FGA check error:", err)
			c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
			return
		}
		c.Next()
	}
}

// create models
func (fga *FGAController) Models(c *gin.Context) {
	var body client.ClientWriteAuthorizationModelRequest
	err := c.Bind(&body)
	if err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	data, err := fga.FgaClient.WriteAuthorizationModel(context.Background()).Body(body).Execute()
	if err != nil {
		log.Println("FGA create model error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	// create tupe in authorization model owner
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
	_, err = fga.FgaClient.Write(context.Background()).Body(bodyTupe).Options(options).Execute()
	if err != nil {
		log.Println("FGA create model owner tuple error:", err, data.AuthorizationModelId)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error, failed to create owner tuple"})
		return
	}
	c.JSON(200, data)
}

// show models
func (fga *FGAController) GetModel(c *gin.Context) {
	modelID := c.Param("id")
	err := fga.FgaClient.SetAuthorizationModelId(modelID)
	if err != nil {
		log.Println("FGA set model id error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	fgaModels, err := fga.FgaClient.ReadAuthorizationModels(context.Background()).Execute()
	if err != nil {
		log.Println("FGA get models error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(200, fgaModels)
	// Implementation for retrieving FGA models
}

// evaluate permissions
func (fga *FGAController) Evaluate(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientCheckRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientCheckOptions{
		AuthorizationModelId: &modeID,
	}
	data, err := fga.FgaClient.Check(context.Background()).
		Body(body).
		Options(options).
		Execute()
	if err != nil {
		log.Println("FGA evaluate error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	if !data.HasAllowed() {
		c.AbortWithStatusJSON(403, gin.H{"error": "Forbidden"})
		return
	}
	c.JSON(200, data)
}

// manage tuples
func (fga *FGAController) Tuples(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientWriteRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientWriteOptions{
		AuthorizationModelId: &modeID,
	}
	_, err := fga.FgaClient.Write(context.Background()).Body(body).Options(options).Execute()
	if err != nil {
		log.Println("FGA create tuples error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(200, gin.H{"status": "tuples created"})
}

// delete tuples
func (fga *FGAController) DeleteTuples(c *gin.Context) {
	modeID := c.Param("id")
	var body client.ClientWriteRequest
	if err := c.BindJSON(&body); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	options := client.ClientWriteOptions{
		AuthorizationModelId: openfga.PtrString(modeID),
	}
	data, err := fga.FgaClient.Write(context.Background()).
		Body(body).
		Options(options).
		Execute()
	if err != nil {
		log.Println("FGA delete tuples error:", err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	c.JSON(200, data)
}
