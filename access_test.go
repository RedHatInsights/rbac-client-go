package rbac

import (
	"context"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const mockApp = "chipotle"

const mockSimpleAccess = `{
	"data": [
	  {
		"resourceDefinitions": [],
		"permission": "chipotle:burrito:order"
	  },
	  {
		"resourceDefinitions": [
		  {
			"attributeFilter": {
			  "key": "beanType",
			  "value": "black",
			  "operation": "equal"
			}
		  }
		],
		"permission": "chipotle:burrito:eat"
	  }
	]
  }`

const mockEmptyAccess = `{
	"data": []
  }`

func TestGetAccess(t *testing.T) {
	// Set up mock service
	var mockBody *[]byte
	var mockStatus *int
	mockService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(*mockStatus)
		w.Write([]byte(*mockBody))
	}))
	defer mockService.Close()

	// Build a client using the mock service
	c := NewClient(mockService.URL, mockApp)

	tests := map[string]struct {
		respBody   []byte
		respStatus int
		expected   AccessList
		ok         bool
	}{
		"simple": {respBody: []byte(mockSimpleAccess), respStatus: 200, ok: true, expected: AccessList{
			Access{Permission: "chipotle:burrito:order", ResourceDefinitions: []ResourceDefinition{}},
			Access{Permission: "chipotle:burrito:eat", ResourceDefinitions: []ResourceDefinition{
				{Filter: ResourceDefinitionFilter{
					Key:       "beanType",
					Value:     "black",
					Operation: "equal",
				}},
			}},
		}},
		"empty": {respBody: []byte(mockEmptyAccess), respStatus: 200, ok: true, expected: AccessList{}},
		"error": {respBody: []byte{}, respStatus: 500, ok: false, expected: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sr := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))

			tracer := provider.Tracer("access-test")
			newCtx, span := tracer.Start(context.Background(), "name")
			defer span.End()

			mockBody = &tc.respBody
			mockStatus = &tc.respStatus
			got, err := c.GetAccess(newCtx, "", "")

			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
			assert.Equal(t, tc.expected, got)

			spans := sr.Ended()
			assert.True(t, spans != nil)

			assert.Equal(t, 1, len(spans))
			s := spans[0]
			att := s.Attributes()
			assert.Equal(t, trace.SpanKindClient, s.SpanKind())
			assert.Equal(t, s.InstrumentationScope().Name, "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp")
			for _, a := range att {
				if a.Key == "http.method" {
					assert.Equal(t, "GET", a.Value.AsString())
				}
			}
		})
	}
}

func TestGetAccess_RequestParams(t *testing.T) {
	identity := "aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQo="
	username := "rick"
	handlerFired := false

	// Set up mock service
	mockService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, identity, r.Header.Get(identityHeader))
		assert.Equal(t, username, r.URL.Query().Get("username"))
		handlerFired = true
	}))
	defer mockService.Close()

	// Build a client and get access using mock service
	c := NewClient(mockService.URL, mockApp)
	c.GetAccess(context.Background(), identity, username)

	// Safety check to ensure the mock service handler was executed
	assert.True(t, handlerFired)
}
