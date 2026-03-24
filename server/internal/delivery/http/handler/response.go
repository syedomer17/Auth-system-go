package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// validationMessages maps validator tags to human-readable error messages.
// Add new entries here as you add new validation tags to your DTOs.
var validationMessages = map[string]string{
	"required": "this field is required",
	"email":    "must be a valid email address",
	"min":      "too short",
	"max":      "too long",
	"alphanum": "must contain only letters and numbers",
}

// formatValidationErrors turns gin/validator errors into a clean field→message map.
//
//	{
//	  "errors": {
//	    "email": "must be a valid email address",
//	    "password": "too short"
//	  }
//	}
func formatValidationErrors(err error) map[string]string {
	fieldErrors := make(map[string]string)

	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		for _, fe := range ve {
			field := fe.Field()
			tag := fe.Tag()

			if msg, ok := validationMessages[tag]; ok {
				fieldErrors[field] = msg
			} else {
				// Fallback: use the tag name itself so the client gets *something*.
				fieldErrors[field] = "failed on: " + tag
			}
		}
	}

	return fieldErrors
}

// bindJSON binds the JSON body into dest and handles validation errors.
// Returns true if binding succeeded, false if an error response was already sent.
// Use this in every handler instead of calling c.ShouldBindJSON directly (DRY).
func bindJSON(c *gin.Context, dest interface{}) bool {
	if err := c.ShouldBindJSON(dest); err != nil {
		// Check if it's a validation error (struct tag failure) vs a parse error (bad JSON).
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"errors": formatValidationErrors(err)})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		}
		return false
	}
	return true
}
