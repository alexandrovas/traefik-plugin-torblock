package traefik_plugin_torblock

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Config — конфигурация плагина.
type Config struct {
	UpdateInterval     string           `json:"updateInterval,omitempty"`
	BlockMessage       string           `json:"blockMessage,omitempty"`
	TorExitNodeListURL string           `json:"torExitNodeListUrl,omitempty"`
	IPStrategy         IpStrategyConfig `json:"ipStrategy"`
	// Redis          RedisConfig `json:"redis"`
}

type IpStrategyConfig struct {
	Depth int `json:"depth"`
}

const (
	xForwardedForHeader = "X-Forwarded-For"
)

// type RedisConfig struct {
// 	Address  string `json:"address,omitempty"`
// 	DB       int    `json:"db,omitempty"`
// 	Username string `json:"username,omitempty"`
// 	Password string `json:"password,omitempty"`
// 	Key      string `json:"key,omitempty"`
// }

// CreateConfig возвращает дефолтную конфигурацию.
func CreateConfig() *Config {
	return &Config{
		UpdateInterval:     "12h",
		BlockMessage:       "Access denied: TOR exit node detected",
		TorExitNodeListURL: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/tor_exits_30d.ipset",
		IPStrategy: IpStrategyConfig{
			Depth: 0,
		},
		// Redis: RedisConfig{
		// 	Key: "traefik:tor_ips",
		// },
	}
}

type TorBlock struct {
	next           http.Handler
	blockMessage   string
	updateInterval time.Duration
	exitListUrl    string
	// interface is not working in yaegi
	// redisStore  *RedisStore
	memoryStore *MemoryStore
	ipStrategy  IpStrategyConfig
	cancel      context.CancelFunc
}

func writeLog(text string, args ...any) {
	msg := "[torblock] " + text + "\n"
	fmt.Printf(msg, args...)
}

// New создаёт экземпляр middleware.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	interval, err := time.ParseDuration(cfg.UpdateInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid update interval: %w", err)
	}

	tb := &TorBlock{
		next:           next,
		blockMessage:   cfg.BlockMessage,
		updateInterval: interval,
		exitListUrl:    cfg.TorExitNodeListURL,
		ipStrategy:     cfg.IPStrategy,
	}

	tb.memoryStore = NewMemoryStore()

	ctx, cancel := context.WithCancel(ctx)
	tb.cancel = cancel

	// запуск фонового обновления
	go tb.updateLoop(ctx)

	return tb, nil
}

// updateLoop периодически обновляет список TOR IP
func (t *TorBlock) updateLoop(ctx context.Context) {
	t.updateTorList()
	ticker := time.NewTicker(t.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.updateTorList()
		case <-ctx.Done():
			return
		}
	}
}

func getAllIPsInCIDR(cidr string) (ips []string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		writeLog("Failed to parse CIDR: %s", err)
	}

	// Iterate through addresses within the prefix
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr.String())
	}
	return
}

// updateTorList скачивает TOR-список и записывает в Store
func (tb *TorBlock) updateTorList() {
	resp, err := http.Get(tb.exitListUrl)
	if err != nil {
		writeLog("Failed to fetch TOR list: %s", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeLog("Failed to read response: %s", err)
		return
	}

	lines := strings.Split(string(body), "\n")
	newIPs := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		ip := strings.TrimSpace(line)
		if ip == "" || strings.HasPrefix(ip, "#") {
			continue
		}
		if strings.Contains(ip, "/") {
			for _, i := range getAllIPsInCIDR(ip) {
				newIPs[i] = struct{}{}
			}
		} else {
			newIPs[ip] = struct{}{}
		}
	}

	tb.memoryStore.Update(newIPs)

	writeLog("Updated TOR IP list (%d entries)", len(newIPs))
}

// Возвращает Client IP
func (tb *TorBlock) getClientIP(req *http.Request) string {
	var result string

	if tb.ipStrategy.Depth > 0 {
		xff := req.Header.Get(xForwardedForHeader)
		if xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) >= tb.ipStrategy.Depth {
				result = parts[len(parts)-tb.ipStrategy.Depth]
			}
		}
	}

	if result == "" {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ip = req.RemoteAddr
		}
		result = ip
	}
	return result
}

// ServeHTTP — проверяет IP и блокирует TOR.
func (tb *TorBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := tb.getClientIP(req)
	blocked := tb.memoryStore.Contains(ip)

	if blocked {
		tb.forbid(rw)
		writeLog("Block request %s %s from TOR IP %s", req.Method, req.RequestURI, ip)
		return
	}

	tb.next.ServeHTTP(rw, req)
}

func (tb *TorBlock) forbid(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte(tb.blockMessage))
}
