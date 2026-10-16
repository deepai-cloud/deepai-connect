package coordinator

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/zstdframe"
)

type Config struct {
	Store        Store
	AdminToken   string
	PollInterval time.Duration
}

type Server struct {
	store       Store
	config      Config
	credentials Credentials
	mux         *http.ServeMux
	mu          sync.Mutex
	sessions    map[string]*mapSession
	connections map[io.Closer]struct{}
	closed      bool
}
type mapSession struct{ cancel context.CancelFunc }
type machineContextKey struct{}

func New(ctx context.Context, c Config) (*Server, error) {
	if c.Store == nil {
		return nil, errors.New("coordinator requires a durable Store")
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	credentials, err := c.Store.LoadOrCreateCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("coordinator credentials: %w", err)
	}
	s := &Server{store: c.Store, config: c, credentials: credentials, mux: http.NewServeMux(), sessions: map[string]*mapSession{}, connections: map[io.Closer]struct{}{}}
	s.mux.HandleFunc("GET /key", s.serveKey)
	s.mux.HandleFunc("/ts2021", s.serveNoise)
	s.mux.HandleFunc("/machine/", s.serveMachine)
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if state, err := s.store.Load(r.Context()); err != nil || state.Revision == "" {
			http.Error(w, "state store unavailable", 503)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.mux.HandleFunc("POST /verify", s.serveVerify)
	s.mux.HandleFunc("/api/v1/", s.serveAdmin)
	return s, nil
}
func (s *Server) Handler() http.Handler        { return s.mux }
func (s *Server) PublicKey() key.MachinePublic { return s.credentials.NoisePrivate.Public() }

// Close also closes hijacked Noise connections, which http.Server.Shutdown
// does not own. Clients then reconnect to another ready coordinator replica.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	connections := make([]io.Closer, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	for _, session := range s.sessions {
		session.cancel()
	}
	s.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	return nil
}

// Update may call change more than once. The callback must be side-effect free
// outside the supplied State; state and callback output are committed together.
func (s *Server) Update(ctx context.Context, change func(*State) error) error {
	for attempt := 0; attempt < 32; attempt++ {
		state, err := s.store.Load(ctx)
		if err != nil {
			return err
		}
		if err = change(state); err != nil {
			return err
		}
		if err = s.store.CompareAndSwap(ctx, state, state.Revision); !errors.Is(err, ErrConflict) {
			return err
		}
		delay := time.Duration(min(attempt+1, 10)) * 5 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("coordinator transaction contention: %w", ErrConflict)
}
func (s *Server) CreateInvitation(ctx context.Context, in Invitation) (string, error) {
	if in.Role != "hub" && in.Role != "worker" && in.Role != "client" {
		return "", errors.New("invalid invitation role")
	}
	if in.Expires.IsZero() {
		in.Expires = time.Now().Add(time.Hour)
	}
	if !time.Now().Before(in.Expires) {
		return "", errors.New("invitation must expire in the future")
	}
	if in.UsesRemaining <= 0 {
		in.UsesRemaining = 1
	}
	in.Created = time.Now().UTC()
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	err = s.Update(ctx, func(st *State) error { copy := in; st.Invitations[TokenHash(token)] = &copy; return nil })
	if err != nil {
		return "", err
	}
	return token, nil
}

// claimInvitation consumes a native auth key and enrolls its public identity
// inside the registration transaction.
func claimInvitation(st *State, token string, n *Node) error {
	invite := st.Invitations[TokenHash(token)]
	if invite == nil || invite.UsesRemaining < 1 || !time.Now().Before(invite.Expires) {
		return ErrUnauthorized
	}
	if n.Role != "" && n.Role != invite.Role {
		return ErrUnauthorized
	}
	n.Role = invite.Role
	if err := AllocateNode(st, n); err != nil {
		return err
	}
	invite.UsesRemaining--
	return nil
}
func (s *Server) serveKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, &tailcfg.OverTLSPublicKeyResponse{PublicKey: s.PublicKey()})
}
func (s *Server) serveNoise(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "GET or POST required", 405)
		return
	}
	conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, s.credentials.NoisePrivate, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.connections[conn] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	h2 := &http2.Server{MaxConcurrentStreams: 32, IdleTimeout: 2 * time.Minute}
	h2.ServeConn(conn, &http2.ServeConnOpts{Context: context.WithValue(r.Context(), machineContextKey{}, conn.Peer()), BaseConfig: &http.Server{Handler: http.HandlerFunc(s.serveMachine), MaxHeaderBytes: 32 << 10}})
}

func decodeRequest(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("one JSON request required")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serveMachine(w http.ResponseWriter, r *http.Request) {
	machine, ok := r.Context().Value(machineContextKey{}).(key.MachinePublic)
	if !ok || machine.IsZero() {
		http.Error(w, "Noise authentication required", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	switch r.URL.Path {
	case "/machine/register":
		s.serveRegister(w, r, machine)
	case "/machine/map":
		s.serveMap(w, r, machine)
	case "/machine/update-health":
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request, machine key.MachinePublic) {
	var req tailcfg.RegisterRequest
	if err := decodeRequest(w, r, &req); err != nil || req.NodeKey.IsZero() || req.Version == 0 {
		http.Error(w, "invalid register request", 400)
		return
	}
	machineText := machine.String()
	expired := false
	err := s.Update(r.Context(), func(st *State) error {
		expired = false
		n := st.Nodes[machineText]
		if n == nil {
			token := ""
			if req.Auth != nil {
				token = req.Auth.AuthKey
			}
			hostname := ""
			if req.Hostinfo != nil {
				hostname = req.Hostinfo.Hostname
			}
			newNode := &Node{MachineKey: machineText, NodeKey: req.NodeKey.String(), Hostname: hostname, Hostinfo: req.Hostinfo, Cap: req.Version}
			return claimInvitation(st, token, newNode)
		}
		if n.Revoked {
			return ErrUnauthorized
		}
		reauthed := false
		if !n.KeyExpiry.IsZero() && !time.Now().Before(n.KeyExpiry) {
			if req.Auth == nil {
				expired = true
				return nil
			}
			invite := st.Invitations[TokenHash(req.Auth.AuthKey)]
			if invite == nil || invite.UsesRemaining < 1 || !time.Now().Before(invite.Expires) || invite.Role != n.Role {
				return ErrUnauthorized
			}
			invite.UsesRemaining--
			n.KeyExpiry = time.Time{}
			reauthed = true
		}
		if n.NodeKey != req.NodeKey.String() {
			if !reauthed && req.OldNodeKey.String() != n.NodeKey {
				return ErrUnauthorized
			}
			for _, peer := range st.Nodes {
				if peer.MachineKey != machineText && peer.NodeKey == req.NodeKey.String() {
					return ErrUnauthorized
				}
			}
			n.NodeKey = req.NodeKey.String()
		}
		if !req.Expiry.IsZero() {
			n.KeyExpiry = req.Expiry
			expired = req.Expiry.Before(time.Now())
		}
		if req.Hostinfo != nil {
			n.Hostinfo = req.Hostinfo
			n.Hostname = safeHostname(req.Hostinfo.Hostname)
		}
		n.Cap = req.Version
		n.LastSeen = time.Now().UTC()
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			writeJSON(w, tailcfg.RegisterResponse{Error: "invalid, expired, or exhausted auth key; administrator enrollment required"})
			return
		}
		http.Error(w, "registration unavailable", 503)
		return
	}
	writeJSON(w, tailcfg.RegisterResponse{User: tailcfg.User{ID: 1, DisplayName: "DeepAI Connect"}, Login: tailcfg.Login{ID: 1, LoginName: "connect", DisplayName: "DeepAI Connect", Provider: "connect"}, MachineAuthorized: !expired, NodeKeyExpired: expired})
}

func (s *Server) authorize(st *State, machine key.MachinePublic, node key.NodePublic) (*Node, error) {
	n := st.Nodes[machine.String()]
	if n == nil || n.NodeKey != node.String() || !active(n, time.Now()) {
		return nil, ErrUnauthorized
	}
	return n, nil
}

func (s *Server) serveMap(w http.ResponseWriter, r *http.Request, machine key.MachinePublic) {
	var req tailcfg.MapRequest
	if err := decodeRequest(w, r, &req); err != nil || req.NodeKey.IsZero() || req.Version == 0 || (req.Compress != "" && req.Compress != "zstd") {
		http.Error(w, "invalid map request", 400)
		return
	}
	st, err := s.store.Load(r.Context())
	if err != nil {
		http.Error(w, "state store unavailable", 503)
		return
	}
	if _, err = s.authorize(st, machine, req.NodeKey); err != nil {
		http.Error(w, "node not authorized", 401)
		return
	}
	if !req.ReadOnly {
		err = s.Update(r.Context(), func(st *State) error {
			n, err := s.authorize(st, machine, req.NodeKey)
			if err != nil {
				return err
			}
			if !(req.Stream && req.Version >= 68) {
				n.Endpoints = validEndpoints(req.Endpoints)
				if !req.DiscoKey.IsZero() {
					n.DiscoKey = req.DiscoKey.String()
				}
				if req.Hostinfo != nil {
					n.Hostinfo = req.Hostinfo
					n.Hostname = safeHostname(req.Hostinfo.Hostname)
				}
			}
			n.Cap = req.Version
			n.LastSeen = time.Now().UTC()
			return nil
		})
		if err != nil {
			http.Error(w, "map update unavailable", 503)
			return
		}
	}
	if req.OmitPeers && !req.Stream && !req.ReadOnly {
		w.WriteHeader(200)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	streaming := req.Stream && !req.ReadOnly
	if streaming {
		session := &mapSession{cancel: cancel}
		s.mu.Lock()
		if prior := s.sessions[machine.String()]; prior != nil {
			prior.cancel()
		}
		s.sessions[machine.String()] = session
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			if s.sessions[machine.String()] == session {
				delete(s.sessions, machine.String())
			}
			s.mu.Unlock()
		}()
	}
	poll := time.NewTicker(s.config.PollInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	w.Header().Set("Content-Type", "application/octet-stream")
	revision := ""
	first := true
	var lastSent time.Time
	for {
		st, err = s.store.Load(ctx)
		if err != nil {
			return
		}
		if _, err = s.authorize(st, machine, req.NodeKey); err != nil {
			return
		}
		if first || st.Revision != revision || time.Since(lastSent) >= 10*time.Second {
			msg, err := MapForState(st, machine.String())
			if err != nil {
				return
			}
			if err = sendMap(w, msg, req.Compress == "zstd"); err != nil {
				return
			}
			revision = st.Revision
			first = false
			lastSent = time.Now()
		}
		if !streaming {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		case <-heartbeat.C:
			if err = s.Update(ctx, func(st *State) error {
				n, err := s.authorize(st, machine, req.NodeKey)
				if err != nil {
					return err
				}
				n.LastSeen = time.Now().UTC()
				return nil
			}); err != nil {
				return
			}
			if req.KeepAlive {
				if err = sendMap(w, &tailcfg.MapResponse{KeepAlive: true}, req.Compress == "zstd"); err != nil {
					return
				}
			}
		}
	}
}

func validEndpoints(endpoints []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, min(len(endpoints), 32))
	for _, ep := range endpoints {
		if len(out) == 32 {
			break
		}
		if ep.IsValid() && ep.Port() != 0 && !ep.Addr().IsUnspecified() && !ep.Addr().IsMulticast() {
			if !slices.Contains(out, ep) {
				out = append(out, ep)
			}
		}
	}
	return out
}

// MapForState constructs the same complete, authorized snapshot for native
// map requests and public host enrollment. Bootstrap must include approved
// return routes and exclude expired identities before the first map refresh.
func MapForState(st *State, machine string) (*tailcfg.MapResponse, error) {
	now := time.Now().UTC()
	self := st.Nodes[machine]
	if self == nil || !active(self, now) {
		return nil, ErrUnauthorized
	}
	peers := []*tailcfg.Node{}
	primary := map[netip.Prefix]uint64{}
	localRoutes := advertisedApproved(self)
	nodes := orderedNodes(st)
	// The first healthy router by stable ID owns each approved route. A
	// single winner prevents ambiguous WireGuard AllowedIPs on host agents.
	for _, n := range nodes {
		if !active(n, now) || now.Sub(n.LastSeen) > 90*time.Second {
			continue
		}
		for _, route := range advertisedApproved(n) {
			if primary[route] == 0 {
				primary[route] = n.ID
			}
		}
	}
	convert := func(n *Node) *tailcfg.Node {
		t := n.TailNode()
		t.Name = nodeName(n, st.Domain)
		for _, route := range advertisedApproved(n) {
			if n.MachineKey != machine && slices.Contains(localRoutes, route) {
				continue
			}
			if primary[route] == n.ID {
				t.AllowedIPs = append(t.AllowedIPs, route)
				t.PrimaryRoutes = append(t.PrimaryRoutes, route)
			}
		}
		return t
	}
	for _, n := range nodes {
		if n.MachineKey != machine && active(n, now) {
			peers = append(peers, convert(n))
		}
	}
	derp := st.DERPMap
	if derp == nil {
		derp = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}}
	}
	policy := st.Policy
	if policy == nil {
		policy = []tailcfg.FilterRule{}
	}
	return &tailcfg.MapResponse{Node: convert(self), Peers: peers, DERPMap: derp, Domain: st.Domain, PacketFilter: policy, DNSConfig: &tailcfg.DNSConfig{}, ControlTime: &now, UserProfiles: []tailcfg.UserProfile{{ID: 1, LoginName: "connect", DisplayName: "DeepAI Connect"}}}, nil
}
func advertisedApproved(n *Node) []netip.Prefix {
	var routes []netip.Prefix
	if n.Hostinfo == nil {
		return routes
	}
	for _, route := range n.ApprovedRoutes {
		if slices.Contains(n.Hostinfo.RoutableIPs, route) {
			routes = append(routes, route)
		}
	}
	return routes
}

func sendMap(w http.ResponseWriter, msg *tailcfg.MapResponse, compress bool) error {
	var b []byte
	var err error
	if msg.KeepAlive {
		b, err = json.Marshal(msg)
	} else {
		// tailcfg's omitempty fields cannot express removing the last peer or
		// denying all traffic. Explicit empty lists are essential on live streams.
		b, err = json.Marshal(struct {
			*tailcfg.MapResponse
			Peers        []*tailcfg.Node
			PacketFilter []tailcfg.FilterRule
		}{msg, msg.Peers, msg.PacketFilter})
	}
	if err != nil {
		return err
	}
	if compress {
		b = zstdframe.AppendEncode(nil, b, zstdframe.FastestCompression)
	}
	if len(b) > 16<<20 {
		return errors.New("map too large")
	}
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(len(b)))
	if _, err = w.Write(prefix[:]); err != nil {
		return err
	}
	if _, err = w.Write(b); err != nil {
		return err
	}
	return http.NewResponseController(w).Flush()
}

func (s *Server) serveVerify(w http.ResponseWriter, r *http.Request) {
	var req tailcfg.DERPAdmitClientRequest
	if err := decodeRequest(w, r, &req); err != nil {
		http.Error(w, "invalid verification", 400)
		return
	}
	st, err := s.store.Load(r.Context())
	if err != nil {
		http.Error(w, "membership unavailable", 503)
		return
	}
	allow := false
	for _, n := range st.Nodes {
		if n.NodeKey == req.NodePublic.String() && active(n, time.Now()) {
			allow = true
			break
		}
	}
	writeJSON(w, tailcfg.DERPAdmitClientResponse{Allow: allow})
}

func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.config.AdminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AdminToken)) != 1 {
		http.Error(w, "administrator authentication required", 401)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/nodes" && r.Method == "GET":
		st, err := s.store.Load(r.Context())
		if err != nil {
			http.Error(w, "state unavailable", 503)
			return
		}
		writeJSON(w, orderedNodes(st))
	case r.URL.Path == "/api/v1/invitations" && r.Method == "POST":
		var invite Invitation
		if err := decodeRequest(w, r, &invite); err != nil {
			http.Error(w, "invalid invitation", 400)
			return
		}
		token, err := s.CreateInvitation(r.Context(), invite)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]string{"token": token})
	case r.URL.Path == "/api/v1/policy" && r.Method == "PUT":
		var policy []tailcfg.FilterRule
		if err := decodeRequest(w, r, &policy); err != nil {
			http.Error(w, "invalid packet policy", 400)
			return
		}
		if err := validatePolicy(policy); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := s.Update(r.Context(), func(st *State) error { st.Policy = policy; return nil }); err != nil {
			http.Error(w, "update failed", 503)
			return
		}
		w.WriteHeader(204)
	case strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && (r.Method == "DELETE" || r.Method == "PUT"):
		machine := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
		var body struct {
			ApprovedRoutes []netip.Prefix `json:"approvedRoutes"`
		}
		if r.Method == "PUT" {
			if err := decodeRequest(w, r, &body); err != nil {
				http.Error(w, "invalid approved routes", 400)
				return
			}
			for _, route := range body.ApprovedRoutes {
				if !route.IsValid() || route != route.Masked() {
					http.Error(w, "routes must be canonical CIDRs", 400)
					return
				}
			}
		}
		err := s.Update(r.Context(), func(st *State) error {
			n := st.Nodes[machine]
			if n == nil {
				return ErrNotFound
			}
			if r.Method == "DELETE" {
				n.Revoked = true
			} else {
				n.ApprovedRoutes = body.ApprovedRoutes
			}
			return nil
		})
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "update failed", 503)
			return
		}
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func validatePolicy(policy []tailcfg.FilterRule) error {
	if len(policy) > 1000 {
		return errors.New("too many packet rules")
	}
	for _, rule := range policy {
		if len(rule.CapGrant) > 0 || len(rule.SrcBits) > 0 {
			return errors.New("capability grants and legacy masks are unsupported")
		}
		for _, src := range rule.SrcIPs {
			if err := validPolicyIP(src); err != nil {
				return err
			}
		}
		for _, dst := range rule.DstPorts {
			if err := validPolicyIP(dst.IP); err != nil {
				return err
			}
			if dst.Ports.First > dst.Ports.Last {
				return errors.New("invalid port range")
			}
		}
		for _, proto := range rule.IPProto {
			if proto < 0 || proto > 255 {
				return errors.New("invalid IP protocol")
			}
		}
	}
	return nil
}
func validPolicyIP(s string) error {
	if s == "*" {
		return nil
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if p, err := netip.ParsePrefix(s); err == nil && p == p.Masked() {
		return nil
	}
	return fmt.Errorf("invalid policy address %q: use an IP, canonical CIDR, or *", s)
}
