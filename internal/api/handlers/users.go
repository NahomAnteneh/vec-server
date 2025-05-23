package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/NahomAnteneh/vec-server/internal/db/models"
)

// UserResponse represents the response format for user operations
type UserResponse struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	IsAdmin   bool   `json:"is_admin"`
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
func RegisterUser(userService models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Email == "" || req.Password == "" {
			http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
			return
		}

		if !isValidEmail(req.Email) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		if !isValidPassword(req.Password) {
			http.Error(w, "Password must be at least 8 characters, with uppercase, lowercase, and numbers", http.StatusBadRequest)
			return
		}

		user, err := models.NewUser(req.Username, req.Email, req.Password)
		if err != nil {
			http.Error(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := userService.Create(user); err != nil {
			http.Error(w, "Failed to register user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		render.Status(r, http.StatusCreated)
		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			IsAdmin:   user.IsAdmin,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// GetUserProfile retrieves user profile information
func GetUserProfile(userService models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")

		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			IsAdmin:   user.IsAdmin,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// UpdateUserProfile updates user settings
func UpdateUserProfile(userService models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")

		if authUser.Username != username {
			http.Error(w, "You can only update your own profile", http.StatusForbidden)
			return
		}

		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		var req UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if req.Email != "" && req.Email != user.Email {
			if !isValidEmail(req.Email) {
				http.Error(w, "Invalid email format", http.StatusBadRequest)
				return
			}
			user.Email = req.Email
		}

		if req.Password != "" {
			if !isValidPassword(req.Password) {
				http.Error(w, "Password must be at least 8 characters, with uppercase, lowercase, and numbers", http.StatusBadRequest)
				return
			}
			if err := user.UpdatePassword(req.Password); err != nil {
				http.Error(w, "Failed to update password: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if err := userService.Update(user); err != nil {
			http.Error(w, "Failed to update user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		render.JSON(w, r, UserResponse{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			IsAdmin:   user.IsAdmin,
			CreatedAt: user.CreatedAt.Format(http.TimeFormat),
		})
	}
}

// DeleteUser handles account deletion
func DeleteUser(userService models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser := auth.GetUserFromContext(r.Context())
		if authUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := chi.URLParam(r, "username")

		if authUser.Username != username && !authUser.IsAdmin {
			http.Error(w, "You can only delete your own account unless you are an admin", http.StatusForbidden)
			return
		}

		user, err := userService.GetByUsername(username)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		if err := userService.Delete(user.ID); err != nil {
			http.Error(w, "Failed to delete user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ListUsers returns a paginated list of users (admin only)
func ListUsers(userService models.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 20
		offset := 0

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

		users, err := userService.List(limit, offset)
		if err != nil {
			http.Error(w, "Failed to list users: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var userResponses []UserResponse
		for _, user := range users {
			userResponses = append(userResponses, UserResponse{
				ID:        user.ID,
				Username:  user.Username,
				Email:     user.Email,
				IsAdmin:   user.IsAdmin,
				CreatedAt: user.CreatedAt.Format(http.TimeFormat),
			})
		}

		render.JSON(w, r, map[string]interface{}{
			"users":       userResponses,
			"next_cursor": offset + len(userResponses),
		})
	}
}

// isValidEmail validates email format
func isValidEmail(email string) bool {
	regex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return regex.MatchString(email)
}

// isValidPassword checks password complexity
func isValidPassword(password string) bool {
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	return len(password) >= 8 && hasUpper && hasLower && hasNumber
}
