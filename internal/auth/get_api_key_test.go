package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-token-123"},
			},
			expectedKey:   "my-secret-token-123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header (Missing ApiKey prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-token-123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header (Too short)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check if the returned key matches expected
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", gotKey, tt.expectedKey)
			}

			// Check if the returned error matches expected
			if err != nil && tt.expectedError == nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
			} else if err == nil && tt.expectedError != nil {
				t.Errorf("GetAPIKey() expected error: %v, got nil", tt.expectedError)
			} else if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedError)
			}
		})
	}
}