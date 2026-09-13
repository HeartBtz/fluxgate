package handler

import (
	"bytes"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"github.com/google/uuid"
	"html/template"
	"mime/multipart"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestManagementFormRejectsMalformedAndLargeBodies(t *testing.T) {
	for _, body := range []string{"password=%zz", "password=" + strings.Repeat("x", 2<<20)} {
		r := httptest.NewRequest("POST", "/web/link", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		if parseSmallForm(w, r) || w.Code != 400 {
			t.Fatalf("malformed form accepted: %d", w.Code)
		}
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("type", "private")
	mw.WriteField("password", "test-password")
	mw.Close()
	r := httptest.NewRequest("POST", "/web/link?type=public", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if !parseSmallForm(httptest.NewRecorder(), r) || r.FormValue("type") != "private" {
		t.Fatal("multipart form or body precedence broken")
	}
}

func TestDashboardEscapesUntrustedNamesAndUsesNonce(t *testing.T) {
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))
	payload := `"><script>alert(1)</script>`
	var output bytes.Buffer
	err := tmpl.ExecuteTemplate(&output, "dashboard.html", pageData{
		User: &domain.User{ID: uuid.New(), Username: payload}, Nonce: "test-nonce",
		Data: dashboardData{Files: []domain.File{{ID: uuid.New(), OriginalName: payload}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), payload) {
		t.Fatal("raw HTML injection rendered")
	}
	if !strings.Contains(output.String(), `<script nonce="test-nonce">`) {
		t.Fatal("script nonce missing")
	}
	if node, err := exec.LookPath("node"); err == nil {
		_, script, _ := strings.Cut(output.String(), `<script nonce="test-nonce">`)
		script, _, _ = strings.Cut(script, "</script>")
		cmd := exec.Command(node, "--check", "-")
		cmd.Stdin = strings.NewReader(script)
		if result, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("rendered JavaScript syntax: %s, %v", result, err)
		}
	} else {
		t.Log("node unavailable; JavaScript syntax check skipped")
	}
}
