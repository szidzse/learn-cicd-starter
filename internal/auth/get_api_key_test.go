package auth

import (
	"errors"
	"net/http"
	"testing"
)

unc TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers     http.Header
		wantKey     string
		wantErr     error
		wantErrText string
	}{
		"valid api key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		"no authorization header": {
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed - missing key value": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			wantErrText: "malformed authorization header",
		},
		"malformed - wrong scheme": {
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			wantKey:     "",
			wantErrText: "malformed authorization header",
		},
		"malformed - empty scheme with space": {
			headers: http.Header{
				"Authorization": []string{" my-secret-key"},
			},
			wantKey:     "",
			wantErrText: "malformed authorization header",
		},
		"valid - extra parts ignored after key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key extra-stuff"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tc.wantKey)
			}

			switch {
			case tc.wantErr != nil:
				if !errors.Is(gotErr, tc.wantErr) {
					t.Errorf("GetAPIKey() err = %v, want %v", gotErr, tc.wantErr)
				}
			case tc.wantErrText != "":
				if gotErr == nil || gotErr.Error() != tc.wantErrText {
					t.Errorf("GetAPIKey() err = %v, want error text %q", gotErr, tc.wantErrText)
				}
			default:
				if gotErr != nil {
					t.Errorf("GetAPIKey() unexpected err = %v", gotErr)
				}
			}
		})
	}
}
