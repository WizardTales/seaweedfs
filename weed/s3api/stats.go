package s3api

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
	stats_collect "github.com/seaweedfs/seaweedfs/weed/stats"
	"go4.org/netipx"
)

type rwClass string

const (
	rwRead  rwClass = "read"
	rwWrite rwClass = "write"
	rwOther rwClass = "other"
)

func buildIPSetFromEnv(env string) *netipx.IPSet {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return nil
	}

	// Support comma OR whitespace separated lists.
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';'
	})

	var b netipx.IPSetBuilder
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			// ignore invalid entries (or log if you have logger)
			continue
		}
		b.AddPrefix(prefix.Masked())
	}
	s, _ := b.IPSet()
	return s
}

var internalSet *netipx.IPSet = buildIPSetFromEnv("S3_INTERNAL_CIDRS")

func _isInternal(ip netip.Addr) bool {
	if internalSet == nil || !ip.IsValid() {
		return false
	}
	return internalSet.Contains(ip)
}

func parseCIDRs(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			// If you have a logger, log warn here. Avoid panics in OSS.
			continue
		}
		out = append(out, p)
	}
	return out
}

func firstXFFAddr(r *http.Request) netip.Addr {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return netip.Addr{}
	}
	// "client, proxy1, proxy2"
	parts := strings.Split(xff, ",")
	if len(parts) == 0 {
		return netip.Addr{}
	}
	ipStr := strings.TrimSpace(parts[0])

	// Strip possible port if someone puts it in (rare, but happens)
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	a, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

func remoteAddr(r *http.Request) netip.Addr {
	ra := strings.TrimSpace(r.RemoteAddr)
	if ra == "" {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(ra)
	if err == nil {
		ra = host
	}
	a, err := netip.ParseAddr(ra)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

func addrInPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func getClientIP(r *http.Request) netip.Addr {
	peer := remoteAddr(r)
	if a := firstXFFAddr(r); a.IsValid() {
		return a
	}
	return peer
}

func classifyReadWrite(action string, r *http.Request) rwClass {
	a := strings.ToLower(action)

	// Prefer action-based mapping. Tune strings to SeaweedFS' action names.
	switch {
	// READ-ish APIs
	case strings.Contains(a, "get"),
		strings.Contains(a, "head"):
		return rwRead

	// WRITE-ish APIs
	case strings.Contains(a, "put"),
		strings.Contains(a, "post"),
		strings.Contains(a, "delete"),
		strings.Contains(a, "copy"),
		strings.Contains(a, "create"),
		strings.Contains(a, "complete"),
		strings.Contains(a, "abort"),
		strings.Contains(a, "uploadpart"),
		strings.Contains(a, "list"),
		strings.Contains(a, "multipart"):
		return rwWrite
	}

	// Fallback
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return rwRead
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		return rwWrite
	default:
		return rwOther
	}
}

func isConditional(r *http.Request) bool {
	// Standard HTTP conditionals
	if r.Header.Get("If-Match") != "" ||
		r.Header.Get("If-None-Match") != "" ||
		r.Header.Get("If-Modified-Since") != "" ||
		r.Header.Get("If-Unmodified-Since") != "" {
		return true
	}
	// S3 copy-source conditionals (if you support them)
	if r.Header.Get("x-amz-copy-source-if-match") != "" ||
		r.Header.Get("x-amz-copy-source-if-none-match") != "" ||
		r.Header.Get("x-amz-copy-source-if-modified-since") != "" ||
		r.Header.Get("x-amz-copy-source-if-unmodified-since") != "" {
		return true
	}
	return false
}

func track(f http.HandlerFunc, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		inFlightGauge := stats_collect.S3InFlightRequestsGauge.WithLabelValues(action)
		inFlightGauge.Inc()
		defer inFlightGauge.Dec()

		bucket, _ := s3_constants.GetBucketAndObject(r)
		// we don't want this...
		// w.Header().Set("Server", "SeaweedFS "+version.VERSION)
		recorder := stats_collect.NewStatusResponseWriter(w)
		start := time.Now()
		f(recorder, r)
		if recorder.Status == http.StatusForbidden {
			bucket = ""
		}
		stats_collect.S3RequestHistogram.WithLabelValues(action, bucket).Observe(time.Since(start).Seconds())
		stats_collect.S3RequestCounter.WithLabelValues(action, strconv.Itoa(recorder.Status), bucket).Inc()
		stats_collect.RecordBucketActiveTime(bucket)

		// NEW: read/write billing counters
		rw := classifyReadWrite(action, r)

		switch rw {
		case rwRead:
			stats_collect.S3ReadCounter.WithLabelValues(bucket).Inc()
		case rwWrite:
			stats_collect.S3WriteCounter.WithLabelValues(bucket).Inc()

			// If your billing model says conditional writes also count a read:
			if isConditional(r) {
				// Option A: count it as a billed read as well
				stats_collect.S3ReadCounter.WithLabelValues(bucket).Inc()
			}
		default:
			// optional: keep an eye on unclassified actions
			stats_collect.S3OtherCounter.WithLabelValues(bucket).Inc()
		}
	}
}

func TimeToFirstByte(action string, start time.Time, r *http.Request) {
	bucket, _ := s3_constants.GetBucketAndObject(r)
	stats_collect.S3TimeToFirstByteHistogram.WithLabelValues(action, bucket).Observe(float64(time.Since(start).Milliseconds()))
	stats_collect.RecordBucketActiveTime(bucket)
}

func BucketTrafficReceived(bytesReceived int64, r *http.Request) {
	bucket, _ := s3_constants.GetBucketAndObject(r)
	stats_collect.RecordBucketActiveTime(bucket)
	stats_collect.S3BucketTrafficReceivedBytesCounter.WithLabelValues(bucket).Add(float64(bytesReceived))
}

func BucketTrafficSent(bytesTransferred int64, r *http.Request) {
	bucket, _ := s3_constants.GetBucketAndObject(r)
	stats_collect.RecordBucketActiveTime(bucket)

	client := getClientIP(r)
	isInternal := _isInternal(client)

	if !isInternal {
		stats_collect.S3BucketExternalSentBytesCounter.WithLabelValues(bucket).
			Add(float64(bytesTransferred))
	}

	stats_collect.S3BucketTrafficSentBytesCounter.WithLabelValues(bucket).Add(float64(bytesTransferred))
}
