package handler

import (
	"net/http"
	"strings"

	"auth-system/internal/usecase"

	"github.com/gin-gonic/gin"
)

// UserHandler handles user profile and admin endpoints.
type UserHandler struct {
	userUC *usecase.UserUsecase
}

func NewUserHandler(userUC *usecase.UserUsecase) *UserHandler {
	return &UserHandler{userUC: userUC}
}

// GetProfile godoc — GET /api/v1/users/me
// Returns the authenticated user's profile.
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetString("userID") // set by Auth middleware

	user, err := h.userUC.GetProfile(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// UpdateProfileRequest is the body for PATCH /api/v1/users/me.
type UpdateProfileRequest struct {
	Name string `json:"name" binding:"required,min=2,max=100"`
}

// UpdateProfile godoc — PATCH /api/v1/users/me
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	var req UpdateProfileRequest
	if !bindJSON(c, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)

	userID := c.GetString("userID")
	if err := h.userUC.UpdateProfile(c.Request.Context(), userID, req.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "profile updated"})
}

// ListUsers godoc — GET /api/v1/users (admin only)
func (h *UserHandler) ListUsers(c *gin.Context) {
	users, err := h.userUC.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// DeleteUser godoc — DELETE /api/v1/users/:id (admin only)
func (h *UserHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")

	if err := h.userUC.DeleteUser(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}
