package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/vec-server/internal/auth"
	"github.com/vec-server/internal/db/models"
)

// UserResponse represents the response format for user operations
type UserResponse struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// RegisterRequest represents the request format for user registration
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// UpdateUserRequest represents the request format for user profile updates
type UpdateUserRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// RegisterUser handles user registration
func RegisterUser(userService *models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Username == "" || req.Email == "" || req.Password == "" {
			http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
			return
		}

		// Validate email format
		if !isValidEmail(req.Email) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		// Validate password complexity
		if !isValidPassword(req.Password) {
			http.Error(w, "Password doesn't meet complexity requirements", http.StatusBadRequest)
			return
		}

		// Create new user
		user, err := models.NewUser(req.Username, req.Email, req.Password)
		if err != nil {
			http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Save user to database
		if err := userService.Create(user); err != nil {
			http.Error(w, "Failed to register user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success response
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// GetUserProfile retrieves user profile information
func GetUserProfile(userService *models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		// Get user by username
		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Return user profile data
		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// UpdateUserProfile updates user settings
func UpdateUserProfile(userService *models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")

		// Check if authenticated user is updating their own profile
		if authUser.Username != username {
			http.Error(w, "You can only update your own profile", http.StatusForbidden)
			return
		}

		// Get user by username
		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Parse request body
		var req UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		// Update user fields if provided
		if req.Email != "" && req.Email != user.Email {
			if !isValidEmail(req.Email) {
				http.Error(w, "Invalid email format", http.StatusBadRequest)
				return
			}
			user.Email = req.Email
		}

		if req.Password != "" {
			if !isValidPassword(req.Password) {
				http.Error(w, "Password doesn't meet complexity requirements", http.StatusBadRequest)
				return
			}
			if err := user.UpdatePassword(req.Password); err != nil {
				http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// Save updated user to database
		if err := userService.Update(user); err != nil {
			http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return updated user data
		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// DeleteUser handles account deletion
func DeleteUser(userService *models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")

		// Check if authenticated user is deleting their own account
		if authUser.Username != username {
			// Check if authenticated user is an admin
			isAdmin := r.Context().Value("isAdmin").(bool)
			if !isAdmin {
				http.Error(w, "You can only delete your own account", http.StatusForbidden)
				return
			}
		}

		// Get user by username
		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Delete user from database
		if err := userService.Delete(user.ID); err != nil {
			http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Return success with no content
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListUsers returns a paginated list of users (admin only)
func ListUsers(userService *models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if authenticated user is an admin
		isAdmin := r.Context().Value("isAdmin").(bool)
		if !isAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		// Parse pagination parameters
		limit := 20 // Default limit
		offset := 0 // Default offset

		limitParam := r.URL.Query().Get("limit")
		if limitParam != "" {
			parsedLimit, err := strconv.Atoi(limitParam)
			if err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}

		offsetParam := r.URL.Query().Get("cursor")
		if offsetParam != "" {
			parsedOffset, err := strconv.Atoi(offsetParam)
			if err == nil && parsedOffset > 0 {
				offset = parsedOffset
			}
		}

		// Get users with pagination
		users, err := userService.List(limit, offset)
		if err != nil {
			http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Format response
		var userResponses []UserResponse
		for _, user := range users {
			userResponses = append(userResponses, UserResponse{
				ID:        user.ID,
				Username:  user.Username,
				Email:     user.Email,
				CreatedAt: user.CreatedAt.Format(http.TimeFormat),
			})
		}

		// Return paginated result
		render.JSON(w, r, map[string]interface{}{
			"users":       userResponses,
			"next_cursor": offset + len(userResponses),
		})
	}
}

// Helper functions

// isValidEmail validates email format
func isValidEmail(email string) bool {
	// Basic validation to ensure email contains @ symbol
	// In a real implementation, use a proper validation library or regex
	return len(email) > 3 && contains(email, "@")
}

// isValidPassword checks password complexity
func isValidPassword(password string) bool {
	// Basic validation for password - require at least 8 characters
	// In a real implementation, check for complexity (uppercase, lowercase, numbers, special chars)
	return len(password) >= 8
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i < len(s); i++ {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
