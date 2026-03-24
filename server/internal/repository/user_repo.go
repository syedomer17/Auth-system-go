package repository

import (
	"context"
	"errors"
	"time"

	"auth-system/internal/domain"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrUserNotFound = errors.New("user not found")
var ErrDuplicateEmail = errors.New("email already exists")

// UserRepository handles all user-related MongoDB operations.
type UserRepository struct {
	col *mongo.Collection
}

func NewUserRepository(db *mongo.Database) *UserRepository {
	col := db.Collection("users")

	// Create unique index on email — prevents duplicate registrations at the DB level.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	return &UserRepository{col: col}
}

// Create inserts a new user. Returns ErrDuplicateEmail if the email is taken.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	if user.Role == "" {
		user.Role = domain.RoleUser
	}

	result, err := r.col.InsertOne(ctx, user)
	if err != nil {
		// Check for duplicate key error (email unique index).
		if mongo.IsDuplicateKeyError(err) {
			return ErrDuplicateEmail
		}
		return err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return nil
}

// FindByEmail looks up a user by email address.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.col.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByID looks up a user by their MongoDB ObjectID.
func (r *UserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	var user domain.User
	err = r.col.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByProvider looks up a user by OAuth provider and provider-specific ID.
func (r *UserRepository) FindByProvider(ctx context.Context, provider, providerID string) (*domain.User, error) {
	var user domain.User
	err := r.col.FindOne(ctx, bson.M{
		"provider":    provider,
		"provider_id": providerID,
	}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindAll returns all users (admin only). Passwords are excluded at the projection level.
func (r *UserRepository) FindAll(ctx context.Context) ([]domain.User, error) {
	cursor, err := r.col.Find(ctx, bson.M{}, options.Find().SetProjection(bson.M{"password": 0}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []domain.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// UpdateName updates the user's display name.
func (r *UserRepository) UpdateName(ctx context.Context, id string, name string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return ErrUserNotFound
	}

	_, err = r.col.UpdateByID(ctx, objID, bson.M{
		"$set": bson.M{"name": name, "updated_at": time.Now()},
	})
	return err
}

// Delete removes a user by ID.
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return ErrUserNotFound
	}

	result, err := r.col.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return err
	}
	if result.DeletedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}
