package metrics

import (
	"context"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"testing"
)

func TestMetricLabelsAreBounded(t *testing.T) {
	r := httptest.NewRequest("ARBITRARY", "/short/user/input", nil)
	if path, method := metricLabels(r); path != "unmatched" || method != "OTHER" {
		t.Fatalf("labels %s %s", path, method)
	}
	ctx := chi.NewRouteContext()
	ctx.RoutePatterns = []string{"/static/*"}
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
	if path, _ := metricLabels(r); path != "/static/*" {
		t.Fatalf("path label %s", path)
	}
}
