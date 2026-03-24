package domain

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User is the core user entity stored in MongoDB.
type User struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email      string             `bson:"email"         json:"email"`
	Password   string             `bson:"password,omitempty" json:"-"` // never exposed in JSON
	Name       string             `bson:"name"          json:"name"`
	Role       string             `bson:"role"          json:"role"`       // "user" | "admin"
	Provider   string             `bson:"provider"      json:"provider"`   // "local" | "google" | "github"
	ProviderID string             `bson:"provider_id,omitempty" json:"-"` // OAuth provider's user ID
	CreatedAt  time.Time          `bson:"created_at"    json:"createdAt"`
	UpdatedAt  time.Time          `bson:"updated_at"    json:"updatedAt"`
}

// Role constants.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// Provider constants.
const (
	ProviderLocal  = "local"
	ProviderGoogle = "google"
	ProviderGithub = "github"
)
