package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/NahomAnteneh/vec-server/internal/auth"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

// Logging middleware adds request logging, performance timing, error logging,
// request ID generation and context enrichment for logging.
func Logging() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Generate a request ID if not already set
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
				r.Header.Set("X-Request-ID", requestID)
			}

			// Store the request ID in the context
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			r = r.WithContext(ctx)

			// Create a response writer wrapper to capture response details
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Log the request
			log.Printf("REQUEST: %s - %s %s - %s - %s",
				requestID,
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
				r.UserAgent(),
			)

			defer func() {
				// Recover from panics
				if rec := recover(); rec != nil {
					// Log the stack trace
					log.Printf("PANIC: %s - %v\n%s", requestID, rec, debug.Stack())

					// Return a 500 Internal Server Error
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, map[string]string{
						"error":      "Internal server error",
						"request_id": requestID,
					})
				}

				// Calculate request duration
				duration := time.Since(start)

				// Get authenticated user if available
				var userDisplay string
				authUser := auth.GetUserFromContext(r.Context())
				if authUser != nil {
					userDisplay = fmt.Sprintf("user_id=%d,username=%s", authUser.ID, authUser.Username)
				} else {
					userDisplay = "anonymous"
				}

				// Log the response
				log.Printf("RESPONSE: %s - %s %s - %d - %s - %dms - %s",
					requestID,
					r.Method,
					r.URL.Path,
					ww.Status(),
					userDisplay,
					duration.Milliseconds(),
					http.StatusText(ww.Status()),
				)
			}()

			// Add response headers
			w.Header().Set("X-Request-ID", requestID)

			// Process the request
			next.ServeHTTP(ww, r)
		})
	}
}

// RequestIDMiddleware extracts or generates a request ID and adds it to the context
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract request ID from header if present
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				// Generate a new request ID
				requestID = uuid.New().String()
				r.Header.Set("X-Request-ID", requestID)
			}

			// Add request ID to response headers
			w.Header().Set("X-Request-ID", requestID)

			// Store in context
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ErrorLogMiddleware logs errors and recovers from panics
func ErrorLogMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					requestID := GetRequestID(r.Context())
					if requestID == "" {
						requestID = "unknown"
					}

					log.Printf("PANIC: %s - %v\n%s", requestID, err, debug.Stack())

					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, map[string]string{
						"error":      "Internal server error",
						"request_id": requestID,
					})
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
