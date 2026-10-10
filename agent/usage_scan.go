package main

// usage_scan.go — the disk usage analyzer of the file explorer (a
// TreeSize-like view: which folders hold the space of a drive, down to the
// file). Four live commands, answered through the WS command channel
// (ExecuteSync) like the other file explorer commands, and blocked by privacy
// mode like them:
//
//   start_usage_scan   {path, restart?}        -> {scanId, root, reused}
//   get_usage_children {scanId, path? | paths?, limit?, files?, filesLimit?}
//                                              -> {scanId, root, state, progress, nodes[]}
//   get_usage_top_files {scanId, limit?}       -> {scanId, state, progress, files[]}
//   cancel_usage_scan  {scanId}                -> {scanId, state}
//
// A scan walks the tree in the background (usageWorkers goroutines, each on
// its own OS thread at background priority where the OS allows it) and keeps
// in memory the DIRECTORIES only: per directory its aggregated size,
// allocated size, file and folder counts and newest modification, plus the
// totals of its own (loose) files. Totals reach every ancestor as soon as a
// chunk of a directory is read, so a reader polling the tree sees the sizes
// grow while the walk goes on; a node is `done` once its whole subtree is.
// The files of one directory are never kept: they are read again from the
// disk when asked (get_usage_children files:true), and only the
// usageTopFiles largest files of the whole scan are remembered.
//
// The walk never follows symbolic links, junctions or mount points (Windows:
// any name-surrogate reparse point; cloud placeholders are real folders and
// are walked) and does not cross into another file system on Unix (same
// st_dev as the root). Entries it cannot read are counted (errors), never
// fatal. Unix: a file with several hard links is counted once.
//
// Allocated size: Unix st_blocks * 512; Windows the size rounded up to the
// volume's cluster, the real on-disk size (GetCompressedFileSizeW) for
// compressed and sparse files only, 0 for offline / cloud-only files (no
// extra I/O for the common case; small files stored inside the MFT are
// counted as one cluster).
//
// Lifetime: one running scan per root (a new start on the same root joins
// it, or replaces it with restart:true), usageMaxRunning running scans per
// agent, usageMaxStored kept, and a scan nobody read for usageExpiry is
// stopped and forgotten. Memory: about 200 bytes per directory plus its
// name; past usageMaxNodes directories the deeper ones are still counted
// but folded into their parent (truncated).

import (
	"container/heap"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	usageWorkers       = 4
	usageMaxRunning    = 2
	usageMaxStored     = 4
	usageExpiry        = 30 * time.Minute
	usageChunk         = 512
	usageTopFiles      = 100
	usageDefaultLimit  = 300
	usageMaxLimit      = 2000
	usageMaxPaths      = 64
	usageDefaultFiles  = 500
	usageMaxFiles      = 5000
	usageIndexMinKids  = 32
	usageJanitorPeriod = time.Minute
	usageOrphanAfter   = 2 * time.Minute // a running scan not read for that long may be replaced
)

// usageNode is one directory of a scan. Every field but name and parent is
// guarded by the scan's mutex.
// usageMaxNodes bounds the folders kept as nodes (a variable for the tests).
var usageMaxNodes = 500000

type usageNode struct {
	name     string
	parent   *usageNode
	children []*usageNode
	index    map[string]*usageNode // by name, built on first lookup in a large folder

	size, alloc    int64 // whole subtree
	files, folders int64 // whole subtree (folders: below this one)
	mtime          int64 // newest file modification in the subtree (unix seconds)

	ownSize, ownAlloc, ownFiles, ownMtime int64 // the loose files of this folder

	errors    int32
	pending   int32 // its own listing + the subfolders not done yet
	done      bool
	listed    bool // its own listing is over
	gone      bool // deleted from the explorer meanwhile (usageForget): detached
	denied    bool // the folder itself could not be read
	truncated bool // deeper folders counted here without nodes (usageMaxNodes)
}

type usageFile struct {
	path  string
	size  int64
	alloc int64
	mtime int64
}

// usageTop is a min-heap by size: the largest files of a scan.
type usageTop []usageFile

func (h usageTop) Len() int            { return len(h) }
func (h usageTop) Less(i, j int) bool  { return h[i].size < h[j].size }
func (h usageTop) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *usageTop) Push(x interface{}) { *h = append(*h, x.(usageFile)) }
func (h *usageTop) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type usageScan struct {
	id      string
	root    string
	rootDev uint64
	hasDev  bool
	cluster int64

	mu       sync.Mutex
	cond     *sync.Cond
	rootNode *usageNode
	queue    []*usageNode
	active   int
	nodes    int
	state    string // running | done | cancelled | error
	errMsg   string
	started  time.Time
	finished time.Time
	lastRead time.Time
	current  string

	filesN, dirsN, bytesN, allocN, errorsN, skippedN int64

	top    usageTop
	topMin atomic.Int64 // the smallest size of a full top list (0 while not full)

	stopped atomic.Int32
	links   map[[2]uint64]struct{}
}

var usageReg = struct {
	sync.Mutex
	scans   map[string]*usageScan
	janitor bool
}{scans: map[string]*usageScan{}}

func usageNewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// usageSameRoot compares two cleaned roots the way the OS does.
func usageSameRoot(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// usageCleanRoot validates and cleans a scan root: absolute, no "..", an
// existing folder. "C:" becomes "C:\".
func usageCleanRoot(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("start_usage_scan: missing path")
	}
	if containsTraversal(p) {
		return "", fmt.Errorf("start_usage_scan: path traversal not allowed")
	}
	if runtime.GOOS == "windows" && len(p) == 2 && p[1] == ':' {
		p += `\`
	}
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("start_usage_scan: the path must be absolute")
	}
	info, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("start_usage_scan: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("start_usage_scan: not a folder")
	}
	return p, nil
}

func (d *CommandDispatcher) handleStartUsageScan(cmd AgentCommand) (interface{}, error) {
	root, err := usageCleanRoot(payloadString(cmd.Payload, "path"))
	if err != nil {
		return nil, err
	}
	restart := payloadBool(cmd.Payload, "restart")
	s, reused, err := usageStart(root, restart)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"scanId": s.id, "root": s.root, "reused": reused}, nil
}

// usageStart joins the running scan of root (restart false) or starts a new
// one (replacing a scan of the same root).
func usageStart(root string, restart bool) (*usageScan, bool, error) {
	usageReg.Lock()
	defer usageReg.Unlock()
	now := time.Now()
	usageSweepLocked(now)
	running := 0
	for id, s := range usageReg.scans {
		st := s.snapshotState()
		if usageSameRoot(s.root, root) {
			if st == "running" && !restart {
				s.touch()
				return s, true, nil
			}
			s.stop("cancelled")
			delete(usageReg.scans, id)
			continue
		}
		if st == "running" {
			running++
		}
	}
	// A running scan nobody reads any more (its explorer closed) gives its
	// place to the new one.
	if running >= usageMaxRunning {
		var oldID string
		var oldAt time.Time
		for id, s := range usageReg.scans {
			if s.snapshotState() != "running" {
				continue
			}
			if at := s.readAt(); now.Sub(at) > usageOrphanAfter && (oldID == "" || at.Before(oldAt)) {
				oldID, oldAt = id, at
			}
		}
		if oldID != "" {
			usageReg.scans[oldID].stop("cancelled")
			running--
		}
	}
	if running >= usageMaxRunning {
		return nil, false, fmt.Errorf("start_usage_scan: %d disk usage scans are already running on this device; stop one first", usageMaxRunning)
	}
	// Keep at most usageMaxStored scans: the finished ones read longest ago go.
	for len(usageReg.scans) >= usageMaxStored {
		var oldID string
		var oldAt time.Time
		for id, s := range usageReg.scans {
			if s.snapshotState() == "running" {
				continue
			}
			at := s.readAt()
			if oldID == "" || at.Before(oldAt) {
				oldID, oldAt = id, at
			}
		}
		if oldID == "" {
			break
		}
		delete(usageReg.scans, oldID)
	}
	s := newUsageScan(root, now)
	usageReg.scans[s.id] = s
	if !usageReg.janitor {
		usageReg.janitor = true
		go usageJanitor()
	}
	s.begin()
	return s, false, nil
}

// usageSweepLocked stops and forgets the scans nobody read for usageExpiry.
func usageSweepLocked(now time.Time) {
	for id, s := range usageReg.scans {
		if now.Sub(s.readAt()) > usageExpiry {
			s.stop("cancelled")
			delete(usageReg.scans, id)
		}
	}
}

func usageJanitor() {
	t := time.NewTicker(usageJanitorPeriod)
	defer t.Stop()
	for range t.C {
		usageReg.Lock()
		usageSweepLocked(time.Now())
		empty := len(usageReg.scans) == 0
		if empty {
			usageReg.janitor = false
		}
		usageReg.Unlock()
		if empty {
			return
		}
	}
}

// usageGet finds a scan by id (and marks it read).
func usageGet(id string) (*usageScan, error) {
	usageReg.Lock()
	s := usageReg.scans[id]
	usageReg.Unlock()
	if s == nil {
		return nil, fmt.Errorf("usage scan not found (expired or replaced): start it again")
	}
	s.touch()
	return s, nil
}

func newUsageScan(root string, now time.Time) *usageScan {
	s := &usageScan{
		id:       usageNewID(),
		root:     root,
		state:    "running",
		started:  now,
		lastRead: now,
		cluster:  usageClusterSize(root),
		links:    map[[2]uint64]struct{}{},
	}
	s.cond = sync.NewCond(&s.mu)
	s.rootNode = &usageNode{name: root, pending: 1}
	s.nodes = 1
	if info, err := os.Stat(root); err == nil {
		s.rootDev, s.hasDev = usageDevice(info)
	}
	return s
}

func (s *usageScan) touch() {
	s.mu.Lock()
	s.lastRead = time.Now()
	s.mu.Unlock()
}

func (s *usageScan) readAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRead
}

func (s *usageScan) snapshotState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *usageScan) isStopped() bool { return s.stopped.Load() != 0 }

// stop ends a running scan (state: cancelled); its tree stays readable.
func (s *usageScan) stop(state string) {
	s.stopped.Store(1)
	s.mu.Lock()
	if s.state == "running" {
		s.state = state
		s.finished = time.Now()
	}
	s.queue = nil
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *usageScan) begin() {
	s.mu.Lock()
	s.queue = append(s.queue, s.rootNode)
	s.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < usageWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker()
		}()
	}
	go func() {
		wg.Wait()
		s.mu.Lock()
		if s.state == "running" {
			s.state = "done"
			s.finished = time.Now()
		}
		s.current = ""
		s.links = nil
		s.mu.Unlock()
	}()
}

func (s *usageScan) worker() {
	// Background priority for this OS thread (usage_scan_windows.go /
	// usage_prio_*.go). The goroutine stays locked to its thread and ends
	// locked: the runtime then ends the thread, so the lowered priority never
	// reaches another goroutine.
	runtime.LockOSThread()
	usageLowPriority()
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			s.errMsg = fmt.Sprintf("internal error: %v", r)
			s.mu.Unlock()
			s.stop("error")
		}
	}()
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && s.active > 0 && !s.isStopped() {
			s.cond.Wait()
		}
		if s.isStopped() || len(s.queue) == 0 {
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
		n := s.queue[len(s.queue)-1]
		s.queue = s.queue[:len(s.queue)-1]
		s.active++
		s.mu.Unlock()

		s.scanDir(n)

		s.mu.Lock()
		s.active--
		if s.active == 0 && len(s.queue) == 0 {
			s.cond.Broadcast()
		}
		s.mu.Unlock()
	}
}

// pathOf rebuilds a node's full path (name and parent never change).
func (s *usageScan) pathOf(n *usageNode) string {
	var names []string
	for x := n; x != nil && x.parent != nil; x = x.parent {
		names = append(names, x.name)
	}
	p := s.root
	for i := len(names) - 1; i >= 0; i-- {
		p = filepath.Join(p, names[i])
	}
	return p
}

// usageBatch: what one chunk of a folder adds.
type usageBatch struct {
	size, alloc, files, mtime int64
	errors, skipped           int64
	dirs                      []string
	top                       []usageFile
}

// readChunk turns directory entries into a batch (no lock held).
func (s *usageScan) readChunk(dir string, ents []os.DirEntry, b *usageBatch) {
	for _, e := range ents {
		if usageIsLink(dir, e) {
			b.skipped++
			continue
		}
		info, err := e.Info()
		if err != nil {
			b.errors++
			continue
		}
		if info.IsDir() {
			if s.hasDev {
				if dev, ok := usageDevice(info); ok && dev != s.rootDev {
					b.skipped++ // another file system mounted here (Unix)
					continue
				}
			}
			b.dirs = append(b.dirs, e.Name())
			continue
		}
		size := info.Size()
		if size < 0 {
			size = 0
		}
		if key, ok := usageLinkKey(info); ok {
			if s.seenLink(key) {
				continue // another name of a file already counted
			}
		}
		alloc := usageAlloc(dir, e.Name(), info, s.cluster)
		mt := info.ModTime().Unix()
		b.size += size
		b.alloc += alloc
		b.files++
		if mt > b.mtime {
			b.mtime = mt
		}
		if size > 0 && size > s.topMin.Load() {
			b.top = append(b.top, usageFile{path: filepath.Join(dir, e.Name()), size: size, alloc: alloc, mtime: mt})
		}
	}
}

func (s *usageScan) seenLink(key [2]uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.links == nil {
		return false
	}
	if _, ok := s.links[key]; ok {
		return true
	}
	s.links[key] = struct{}{}
	return false
}

// addLocked: a batch reaches the node, its ancestors and the counters.
func (s *usageScan) addLocked(n *usageNode, b *usageBatch, own bool) {
	if own {
		n.ownSize += b.size
		n.ownAlloc += b.alloc
		n.ownFiles += b.files
		if b.mtime > n.ownMtime {
			n.ownMtime = b.mtime
		}
	}
	for x := n; x != nil; x = x.parent {
		x.size += b.size
		x.alloc += b.alloc
		x.files += b.files
		if b.mtime > x.mtime {
			x.mtime = b.mtime
		}
		if x.gone {
			break // a detached subtree reaches no ancestor any more
		}
	}
	n.errors += int32(b.errors)
	s.filesN += b.files
	s.bytesN += b.size
	s.allocN += b.alloc
	s.errorsN += b.errors
	s.skippedN += b.skipped
	for _, f := range b.top {
		if len(s.top) < usageTopFiles {
			heap.Push(&s.top, f)
		} else if f.size > s.top[0].size {
			s.top[0] = f
			heap.Fix(&s.top, 0)
		}
	}
	if len(s.top) >= usageTopFiles {
		s.topMin.Store(s.top[0].size)
	}
}

// addFoldersLocked: count new folders below n in n and its ancestors.
func addFoldersLocked(n *usageNode, k int64) {
	for x := n; x != nil; x = x.parent {
		x.folders += k
		if x.gone {
			break
		}
	}
}

// finishLocked: one pending part of n is over (its listing, or a
// subfolder); done climbs up as far as it goes.
func finishLocked(n *usageNode) {
	for x := n; x != nil; x = x.parent {
		x.pending--
		if x.pending > 0 {
			return
		}
		x.done = true
		if x.gone {
			return // its parent stopped waiting for it when it was detached
		}
	}
}

func (s *usageScan) scanDir(n *usageNode) {
	dir := s.pathOf(n)
	s.mu.Lock()
	s.current = dir
	s.mu.Unlock()
	f, err := os.Open(usageLongPath(dir))
	if err != nil {
		s.mu.Lock()
		n.denied = true
		n.errors++
		s.errorsN++
		finishLocked(n)
		s.mu.Unlock()
		return
	}
	defer f.Close()
	for !s.isStopped() {
		ents, rerr := f.ReadDir(usageChunk)
		var b usageBatch
		s.readChunk(dir, ents, &b)
		if rerr != nil && rerr != io.EOF {
			b.errors++
		}
		var collapsed []string
		s.mu.Lock()
		s.addLocked(n, &b, true)
		for _, name := range b.dirs {
			if s.nodes >= usageMaxNodes {
				collapsed = append(collapsed, name)
				continue
			}
			c := &usageNode{name: name, parent: n, pending: 1}
			n.children = append(n.children, c)
			n.pending++
			s.nodes++
			s.queue = append(s.queue, c)
		}
		if k := int64(len(b.dirs)); k > 0 {
			addFoldersLocked(n, k)
			s.dirsN += k
			s.cond.Broadcast()
		}
		if len(collapsed) > 0 {
			n.truncated = true
		}
		s.mu.Unlock()
		for _, name := range collapsed {
			s.walkCollapsed(n, filepath.Join(dir, name), 0)
		}
		if rerr != nil || len(ents) == 0 {
			break
		}
	}
	s.mu.Lock()
	n.listed = true
	finishLocked(n)
	s.mu.Unlock()
}

// walkCollapsed counts a folder past usageMaxNodes into n (no node of its
// own), recursively, in this worker.
func (s *usageScan) walkCollapsed(n *usageNode, dir string, depth int) {
	if s.isStopped() || depth > 256 {
		return
	}
	f, err := os.Open(usageLongPath(dir))
	if err != nil {
		s.mu.Lock()
		n.errors++
		s.errorsN++
		s.mu.Unlock()
		return
	}
	defer f.Close()
	for !s.isStopped() {
		ents, rerr := f.ReadDir(usageChunk)
		var b usageBatch
		s.readChunk(dir, ents, &b)
		if rerr != nil && rerr != io.EOF {
			b.errors++
		}
		s.mu.Lock()
		s.addLocked(n, &b, false)
		if k := int64(len(b.dirs)); k > 0 {
			addFoldersLocked(n, k)
			s.dirsN += k
		}
		s.mu.Unlock()
		for _, name := range b.dirs {
			s.walkCollapsed(n, filepath.Join(dir, name), depth+1)
		}
		if rerr != nil || len(ents) == 0 {
			break
		}
	}
}

// ── Reading a scan ───────────────────────────────────────────────────────────

func usageTime(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func (s *usageScan) progressLocked() map[string]interface{} {
	end := time.Now()
	if !s.finished.IsZero() {
		end = s.finished
	}
	p := map[string]interface{}{
		"files":     s.filesN,
		"folders":   s.dirsN,
		"bytes":     s.bytesN,
		"allocated": s.allocN,
		"errors":    s.errorsN,
		"skipped":   s.skippedN,
		"current":   s.current,
		"elapsedMs": end.Sub(s.started).Milliseconds(),
		"startedAt": s.started.UTC().Format(time.RFC3339),
	}
	if !s.finished.IsZero() {
		p["finishedAt"] = s.finished.UTC().Format(time.RFC3339)
	}
	return p
}

func (s *usageScan) nodeJSONLocked(n *usageNode, path string) map[string]interface{} {
	return map[string]interface{}{
		"name":       n.name,
		"path":       path,
		"size":       n.size,
		"allocated":  n.alloc,
		"files":      n.files,
		"folders":    n.folders,
		"modified":   usageTime(n.mtime),
		"done":       n.done,
		"denied":     n.denied,
		"errors":     n.errors,
		"truncated":  n.truncated,
		"childCount": len(n.children),
	}
}

// findLocked resolves a path of this scan to its node (nil: not a folder of
// this scan).
func (s *usageScan) findLocked(p string) *usageNode {
	p = filepath.Clean(p)
	if usageSameRoot(p, s.root) {
		return s.rootNode
	}
	rel, err := filepath.Rel(s.root, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil
	}
	n := s.rootNode
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		n = childLocked(n, part)
		if n == nil {
			return nil
		}
	}
	return n
}

func childLocked(n *usageNode, name string) *usageNode {
	if len(n.children) >= usageIndexMinKids {
		if n.index == nil || len(n.index) != len(n.children) {
			n.index = make(map[string]*usageNode, len(n.children))
			for _, c := range n.children {
				n.index[c.name] = c
			}
		}
		if c := n.index[name]; c != nil {
			return c
		}
	} else {
		for _, c := range n.children {
			if c.name == name {
				return c
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, c := range n.children {
			if strings.EqualFold(c.name, name) {
				return c
			}
		}
	}
	return nil
}

func payloadInt(payload map[string]interface{}, key string, def, hi int) int {
	v, ok := payload[key].(float64)
	if !ok || v < 1 {
		return def
	}
	if int(v) > hi {
		return hi
	}
	return int(v)
}

func (d *CommandDispatcher) handleGetUsageChildren(cmd AgentCommand) (interface{}, error) {
	s, err := usageGet(payloadString(cmd.Payload, "scanId"))
	if err != nil {
		return nil, fmt.Errorf("get_usage_children: %w", err)
	}
	limit := payloadInt(cmd.Payload, "limit", usageDefaultLimit, usageMaxLimit)
	var paths []string
	if raw, ok := cmd.Payload["paths"].([]interface{}); ok {
		for _, v := range raw {
			if p, ok := v.(string); ok && p != "" && len(paths) < usageMaxPaths {
				paths = append(paths, p)
			}
		}
	}
	if p := payloadString(cmd.Payload, "path"); p != "" && len(paths) < usageMaxPaths {
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		paths = []string{s.root}
	}
	withFiles := payloadBool(cmd.Payload, "files")
	filesLimit := payloadInt(cmd.Payload, "filesLimit", usageDefaultFiles, usageMaxFiles)

	type want struct {
		path  string
		entry map[string]interface{}
	}
	wants := make([]want, 0, len(paths))
	out := make([]map[string]interface{}, 0, len(paths))
	s.mu.Lock()
	for _, p := range paths {
		var n *usageNode
		if !containsTraversal(p) {
			n = s.findLocked(p)
		}
		entry := map[string]interface{}{"path": p, "found": n != nil}
		if n != nil {
			np := s.pathOf(n)
			entry["path"] = np
			entry["node"] = s.nodeJSONLocked(n, np)
			kids := make([]*usageNode, len(n.children))
			copy(kids, n.children)
			sort.Slice(kids, func(i, j int) bool {
				if kids[i].size != kids[j].size {
					return kids[i].size > kids[j].size
				}
				return kids[i].name < kids[j].name
			})
			if len(kids) > limit {
				kids = kids[:limit]
			}
			cs := make([]map[string]interface{}, 0, len(kids))
			for _, c := range kids {
				cs = append(cs, s.nodeJSONLocked(c, filepath.Join(np, c.name)))
			}
			entry["children"] = cs
			entry["childrenTotal"] = len(n.children)
			entry["filesGroup"] = map[string]interface{}{
				"count":     n.ownFiles,
				"size":      n.ownSize,
				"allocated": n.ownAlloc,
				"modified":  usageTime(n.ownMtime),
			}
			wants = append(wants, want{np, entry})
		}
		out = append(out, entry)
	}
	res := map[string]interface{}{
		"scanId":   s.id,
		"root":     s.root,
		"state":    s.state,
		"error":    s.errMsg,
		"progress": s.progressLocked(),
		"nodes":    out,
	}
	s.mu.Unlock()
	// The loose files of a folder: read again from the disk (never kept).
	if withFiles {
		for _, w := range wants {
			files, total, ferr := usageListFiles(w.path, filesLimit, s.cluster)
			w.entry["files"] = files
			w.entry["filesTotal"] = total
			if ferr != nil {
				w.entry["filesError"] = ferr.Error()
			}
		}
	}
	return res, nil
}

// usageListFiles: the files (no folders, no links) of dir, largest first.
func usageListFiles(dir string, limit int, cluster int64) ([]map[string]interface{}, int, error) {
	ents, err := os.ReadDir(usageLongPath(dir))
	type fe struct {
		name        string
		size, alloc int64
		mtime       int64
	}
	var list []fe
	for _, e := range ents {
		if e.IsDir() || usageIsLink(dir, e) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || info.IsDir() {
			continue
		}
		list = append(list, fe{e.Name(), info.Size(), usageAlloc(dir, e.Name(), info, cluster), info.ModTime().Unix()})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].size != list[j].size {
			return list[i].size > list[j].size
		}
		return list[i].name < list[j].name
	})
	total := len(list)
	if len(list) > limit {
		list = list[:limit]
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, f := range list {
		out = append(out, map[string]interface{}{
			"name": f.name, "path": filepath.Join(dir, f.name), "size": f.size, "allocated": f.alloc, "modified": usageTime(f.mtime),
		})
	}
	if err != nil && len(out) == 0 {
		return out, total, err
	}
	return out, total, nil
}

func (d *CommandDispatcher) handleGetUsageTopFiles(cmd AgentCommand) (interface{}, error) {
	s, err := usageGet(payloadString(cmd.Payload, "scanId"))
	if err != nil {
		return nil, fmt.Errorf("get_usage_top_files: %w", err)
	}
	limit := payloadInt(cmd.Payload, "limit", usageTopFiles, usageTopFiles)
	s.mu.Lock()
	top := make([]usageFile, len(s.top))
	copy(top, s.top)
	res := map[string]interface{}{
		"scanId":   s.id,
		"root":     s.root,
		"state":    s.state,
		"error":    s.errMsg,
		"progress": s.progressLocked(),
	}
	s.mu.Unlock()
	sort.Slice(top, func(i, j int) bool {
		if top[i].size != top[j].size {
			return top[i].size > top[j].size
		}
		return top[i].path < top[j].path
	})
	if len(top) > limit {
		top = top[:limit]
	}
	files := make([]map[string]interface{}, 0, len(top))
	for _, f := range top {
		files = append(files, map[string]interface{}{
			"name": filepath.Base(f.path), "path": f.path, "size": f.size, "allocated": f.alloc, "modified": usageTime(f.mtime),
		})
	}
	res["files"] = files
	return res, nil
}

func (d *CommandDispatcher) handleCancelUsageScan(cmd AgentCommand) (interface{}, error) {
	s, err := usageGet(payloadString(cmd.Payload, "scanId"))
	if err != nil {
		return nil, fmt.Errorf("cancel_usage_scan: %w", err)
	}
	s.stop("cancelled")
	return map[string]interface{}{"scanId": s.id, "state": s.snapshotState()}, nil
}

// usageStopAll stops every running scan (privacy mode turned on: what the
// explorer may no longer browse is not walked any further). Their trees
// stay readable only with the privacy unlock, like any explorer command.
func usageStopAll() {
	usageReg.Lock()
	defer usageReg.Unlock()
	for _, s := range usageReg.scans {
		s.stop("cancelled")
	}
}

// usageForget takes a file or folder deleted from the explorer out of every
// scan that counted it, so the analyzer shows the space it freed at once.
// A folder is detached with its whole subtree (what its walk still adds stops
// at it); a file is taken out of its folder's loose files once that folder's
// listing is over (before, it may not have been counted yet).
func usageForget(p string, info os.FileInfo) {
	p = filepath.Clean(p)
	usageReg.Lock()
	scans := make([]*usageScan, 0, len(usageReg.scans))
	for _, s := range usageReg.scans {
		scans = append(scans, s)
	}
	usageReg.Unlock()
	for _, s := range scans {
		s.forget(p, info)
	}
}

func (s *usageScan) forget(p string, info os.FileInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info.IsDir() {
		n := s.findLocked(p)
		if n == nil || n.parent == nil {
			return
		}
		par := n.parent
		for i, c := range par.children {
			if c == n {
				par.children = append(par.children[:i], par.children[i+1:]...)
				break
			}
		}
		par.index = nil
		n.gone = true
		for x := par; x != nil; x = x.parent {
			x.size -= n.size
			x.alloc -= n.alloc
			x.files -= n.files
			x.folders -= n.folders + 1
			if x.gone {
				break
			}
		}
		if !n.done {
			finishLocked(par)
		}
		s.dropTopLocked(func(fp string) bool {
			rel, err := filepath.Rel(p, fp)
			return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
		})
		return
	}
	par := s.findLocked(filepath.Dir(p))
	if par == nil || !par.listed {
		return
	}
	size := info.Size()
	alloc := usageAlloc(filepath.Dir(p), filepath.Base(p), info, s.cluster)
	par.ownSize -= size
	par.ownAlloc -= alloc
	par.ownFiles--
	for x := par; x != nil; x = x.parent {
		x.size -= size
		x.alloc -= alloc
		x.files--
		if x.gone {
			break
		}
	}
	s.dropTopLocked(func(fp string) bool { return usageSameRoot(fp, p) })
}

// dropTopLocked removes from the largest files those that match.
func (s *usageScan) dropTopLocked(match func(string) bool) {
	kept := s.top[:0]
	for _, f := range s.top {
		if !match(f.path) {
			kept = append(kept, f)
		}
	}
	s.top = kept
	heap.Init(&s.top)
	if len(s.top) < usageTopFiles {
		s.topMin.Store(0)
	}
}
