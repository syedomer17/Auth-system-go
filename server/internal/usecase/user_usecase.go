package usecase

import (
	"context"

	"auth-system/internal/domain"
	"auth-system/internal/repository"
)

// UserUsecase contains user profile and admin business logic.
type UserUsecase struct {
	userRepo *repository.UserRepository
}

func NewUserUsecase(userRepo *repository.UserRepository) *UserUsecase {
	return &UserUsecase{userRepo: userRepo}
}

// GetProfile returns the user's own profile by ID.
func (u *UserUsecase) GetProfile(ctx context.Context, userID string) (*domain.User, error) {
	return u.userRepo.FindByID(ctx, userID)
}

// UpdateProfile allows users to update their own name.
func (u *UserUsecase) UpdateProfile(ctx context.Context, userID string, name string) error {
	return u.userRepo.UpdateName(ctx, userID, name)
}

// ListUsers returns all users (admin-only operation — enforced by RBAC middleware).
func (u *UserUsecase) ListUsers(ctx context.Context) ([]domain.User, error) {
	return u.userRepo.FindAll(ctx)
}

// DeleteUser removes a user by ID (admin-only).
func (u *UserUsecase) DeleteUser(ctx context.Context, userID string) error {
	return u.userRepo.Delete(ctx, userID)
}
