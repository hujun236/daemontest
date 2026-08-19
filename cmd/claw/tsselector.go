package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	serversURL       = "https://cfg.clianywhere.com/servers.json"
	serversCacheDir  = ".clianywhere"
	serversCacheFile = "servers.json"
	healthThreshold  = 0.99

	// location cache: ~/.clianywhere/location.cache, format "num|unix_seconds"
	locationCacheFile = "location.cache"
	locationTTL       = 24 * time.Hour

	// continent lookup endpoint (served by globalserver_worker)
	checkLocationURL = "https://globalserver.clianywhere.com/api/checklocation"

	// default continent number (fallback on miss/no-cache, corresponds to NA)
	defaultLocationNum = 5
)

// forceTSAddr package-level override, set from Config.ForceTSAddr at startup
var forceTSAddr string

// SetForceTSAddr set the forced TS address (called once at startup)
func SetForceTSAddr(addr string) {
	forceTSAddr = addr
}

// loadForceTSAddr returns the forced TS address if set
func loadForceTSAddr() string {
	return forceTSAddr
}

// ServerEntry from servers.json
type ServerEntry struct {
	Addr   string `json:"addr"`
	Health string `json:"health"`
}

// HealthResponse from TS /health endpoint
// health = daemonCount / maxDaemonCount, i.e. load ratio; lower means more idle
type HealthResponse struct {
	Alive        bool    `json:"alive"`
	BrowserCount int     `json:"browser_count"`
	Health       float64 `json:"health"`
}

// probeResult latency probe result for one TS
type probeResult struct {
	server  ServerEntry
	latency time.Duration
	health  float64
	alive   bool
	err     error
}

// cachePath returns the full path for the cached servers.json
func cachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, serversCacheDir, serversCacheFile), nil
}

// locationCachePath returns the full path for the location cache file
func locationCachePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, serversCacheDir, locationCacheFile), nil
}

// downloadServers downloads servers.json from remote and saves to cache file.
// Returns the raw bytes. Caller handles errors / fallback.
func downloadServers() ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(serversURL)
	if err != nil {
		return nil, fmt.Errorf("download servers.json failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download servers.json status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read servers.json failed: %w", err)
	}

	// validate: must be a JSON object mapping continent number (as string key) -> []ServerEntry
	var tmp map[string][]ServerEntry
	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, fmt.Errorf("invalid servers.json: %w", err)
	}

	if err := saveCache(data); err != nil {
		_ = err
	}

	return data, nil
}

// saveCache writes data to the local cache file
func saveCache(data []byte) error {
	path, err := cachePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	return os.WriteFile(path, data, 0644)
}

// loadCachedServers reads servers.json from local cache file
func loadCachedServers() (map[string][]ServerEntry, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cached servers.json failed: %w", err)
	}
	var servers map[string][]ServerEntry
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("parse cached servers.json failed: %w", err)
	}
	return servers, nil
}

// FetchServers downloads servers.json, falls back to cached copy on failure.
// Returns a map of continent number (string "1".."7") -> []ServerEntry.
func FetchServers(logger Logger) (map[string][]ServerEntry, error) {
	data, err := downloadServers()
	if err != nil {
		if logger != nil {
			logger.Warnf("[TS] download servers.json failed: %v, trying cache", err)
		}
		cached, cerr := loadCachedServers()
		if cerr != nil {
			return nil, fmt.Errorf("download failed (%v) and cache unavailable (%v)", err, cerr)
		}
		if logger != nil {
			logger.Infof("[TS] using cached servers.json (%d regions)", len(cached))
		}
		return cached, nil
	}

	var servers map[string][]ServerEntry
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("parse servers.json failed: %w", err)
	}

	if logger != nil {
		logger.Infof("[TS] downloaded servers.json (%d regions)", len(servers))
	}
	return servers, nil
}

// ---- Location (continent) lookup: 24h local cache + checklocation endpoint ----

// loadLocationCache reads the local location cache, returns (num, unixSeconds, ok).
// ok=false means the file is missing or malformed.
func loadLocationCache() (num int, ts int64, ok bool) {
	path, err := locationCachePath()
	if err != nil {
		return 0, 0, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimSpace(string(data)), "|")
	if len(parts) != 2 {
		return 0, 0, false
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 || n > 7 {
		return 0, 0, false
	}
	t, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || t <= 0 {
		return 0, 0, false
	}
	return n, t, true
}

// saveLocationCache writes the location cache, format "num|unix_seconds"
func saveLocationCache(num int, ts int64) error {
	path, err := locationCachePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d|%d", num, ts)), 0600)
}

// fetchCheckLocation calls globalserver's /api/checklocation endpoint to get the continent number.
// Response format: {"c": N}, N in 1..7
func fetchCheckLocation() (int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", checkLocationURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "CliAnyWhere/daemon")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("checklocation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("checklocation status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	var payload struct {
		C int `json:"c"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("parse checklocation response failed: %w (body=%s)", err, string(body))
	}
	if payload.C < 1 || payload.C > 7 {
		return 0, fmt.Errorf("checklocation returned invalid number: %d", payload.C)
	}
	return payload.C, nil
}

// GetLocalInfo returns the continent number (1-7) of this machine.
// Uses the local cache first (valid for 24h); on expiry or absence, fetches via
// /api/checklocation and persists the result.
// On fetch failure: falls back to the expired cache; if no cache exists, returns 5 (NA).
func GetLocalInfo(logger Logger) (int, error) {
	// 1. local cache
	if cachedNum, cachedTs, ok := loadLocationCache(); ok {
		age := time.Since(time.Unix(cachedTs, 0))
		if age < locationTTL {
			return cachedNum, nil
		}
		if logger != nil {
			logger.Infof("[loc] cache expired (age=%s), refetching", age.Round(time.Second))
		}
	}

	// 2. fetch
	num, err := fetchCheckLocation()
	if err != nil {
		if logger != nil {
			logger.Warnf("[loc] checklocation failed: %v", err)
		}
		// fallback 1: expired cache
		if cachedNum, _, ok := loadLocationCache(); ok {
			if logger != nil {
				logger.Warnf("[loc] falling back to expired cache: %d", cachedNum)
			}
			return cachedNum, nil
		}
		// fallback 2: default NA
		if logger != nil {
			logger.Warnf("[loc] no cache available, defaulting to %d (NA)", defaultLocationNum)
		}
		return defaultLocationNum, nil
	}

	// 3. save
	if err := saveLocationCache(num, time.Now().Unix()); err != nil {
		if logger != nil {
			logger.Warnf("[loc] failed to save cache: %v", err)
		}
	}
	if logger != nil {
		logger.Infof("[loc] fetched location: %d", num)
	}
	return num, nil
}

// probeServer probes a single TS server: call health URL twice, record second call latency
func probeServer(server ServerEntry, logger Logger) probeResult {
	result := probeResult{server: server}
	addr := server.Addr

	client := &http.Client{Timeout: 5 * time.Second}

	// first call — warm up DNS, discard timing
	if logger != nil {
		logger.Debugf("[TS] probing %s (warmup request)", addr)
	}
	resp, err := client.Get(server.Health)
	if err != nil {
		result.err = fmt.Errorf("first health check failed: %w", err)
		if logger != nil {
			logger.Warnf("[TS] %s warmup request failed: %v", addr, err)
		}
		return result
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// second call — measure latency
	if logger != nil {
		logger.Debugf("[TS] probing %s (measuring latency)", addr)
	}
	start := time.Now()
	resp, err = client.Get(server.Health)
	if err != nil {
		result.err = fmt.Errorf("second health check failed: %w", err)
		if logger != nil {
			logger.Warnf("[TS] %s latency request failed: %v", addr, err)
		}
		return result
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	result.latency = time.Since(start)

	var hr HealthResponse
	if err := json.Unmarshal(body, &hr); err != nil {
		result.err = fmt.Errorf("parse health response failed: %w", err)
		return result
	}

	result.alive = hr.Alive
	result.health = hr.Health

	if logger != nil {
		logger.Infof("[TS] %s latency=%dms health=%.4f alive=%v browsers=%d",
			addr, result.latency.Milliseconds(), result.health, result.alive, hr.BrowserCount)
	}

	return result
}

// SelectBestTurnServer full TS selection flow:
//  1. ForceTSAddr short-circuit (forced via env)
//  2. GetLocalInfo to get the continent number (1-7)
//  3. Fetch servers.json, look up this continent's server list by numeric key ("1".."7")
//  4. Probe each /health concurrently; pick the lowest health (load ratio, lower=more idle);
//     tie-break by lowest latency; if the continent has no servers, fall back to "5" (NA)
func SelectBestTurnServer(logger Logger) (*TurnServerEntry, error) {
	// ForceTSAddr short-circuit
	if cfg := loadForceTSAddr(); cfg != "" {
		if logger != nil {
			logger.Infof("[TS] ForceTSAddr set, using %s directly", cfg)
		}
		return &TurnServerEntry{Addr: cfg}, nil
	}

	// 1. get continent number
	num, _ := GetLocalInfo(logger)
	regionKey := strconv.Itoa(num)

	// 2. fetch servers.json
	all, err := FetchServers(logger)
	if err != nil {
		return nil, err
	}

	// 3. look up this continent's servers; fall back to "5" (NA) if empty
	servers := all[regionKey]
	if len(servers) == 0 && regionKey != strconv.Itoa(defaultLocationNum) {
		if logger != nil {
			logger.Warnf("[TS] no servers in region %s, fallback to %d", regionKey, defaultLocationNum)
		}
		regionKey = strconv.Itoa(defaultLocationNum)
		servers = all[regionKey]
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers available for region %s", regionKey)
	}

	// single server in this region: use it directly, skip health probe.
	// no alternative to pick anyway; if it's down the WebSocket dial will fail
	// and the relay loop's reconnect backoff takes over.
	if len(servers) == 1 {
		if logger != nil {
			logger.Infof("[TS] only one server in region %s, using %s directly", regionKey, servers[0].Addr)
		}
		return &TurnServerEntry{Addr: servers[0].Addr}, nil
	}

	// 4. probe /health concurrently
	results := make([]probeResult, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(idx int, srv ServerEntry) {
			defer wg.Done()
			results[idx] = probeServer(srv, logger)
		}(i, s)
	}
	wg.Wait()

	// candidates: alive && health < 0.99
	var candidates []*probeResult
	for i := range results {
		r := &results[i]
		if r.err != nil {
			if logger != nil {
				logger.Warnf("[TS] server %s probe failed: %v", r.server.Addr, r.err)
			}
			continue
		}
		if !r.alive {
			if logger != nil {
				logger.Warnf("[TS] server %s not alive", r.server.Addr)
			}
			continue
		}
		if r.health >= healthThreshold {
			if logger != nil {
				logger.Warnf("[TS] server %s health=%.4f >= %.2f, skipping", r.server.Addr, r.health, healthThreshold)
			}
			continue
		}
		candidates = append(candidates, r)
	}

	// fallback: no healthy candidate; take the least-loaded among successfully probed
	if len(candidates) == 0 {
		for i := range results {
			r := &results[i]
			if r.err != nil {
				continue
			}
			candidates = append(candidates, r)
		}
		if len(candidates) > 0 && logger != nil {
			logger.Warnf("[TS] no healthy server in region %s, fallback to least-loaded among probed", regionKey)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no server available among %d candidates in region %s (all probes failed)", len(servers), regionKey)
	}

	// prefer lowest health; tie-break by lowest latency
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].health != candidates[j].health {
			return candidates[i].health < candidates[j].health
		}
		return candidates[i].latency < candidates[j].latency
	})
	best := candidates[0]

	if logger != nil {
		logger.Infof("[TS] selected %s (region=%s, health=%.4f, latency=%dms) from %d candidates",
			best.server.Addr, regionKey, best.health, best.latency.Milliseconds(), len(servers))
	}

	return &TurnServerEntry{Addr: best.server.Addr}, nil
}
