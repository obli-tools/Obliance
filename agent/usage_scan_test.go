package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// usageTree builds:
//
//	root/f0          50 B
//	root/a/f1       100 B
//	root/a/b/f2     300 B
//	root/a/b/big   4000 B
//	root/c/          (empty)
func usageTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel string, n int) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("f0", 50)
	write(filepath.Join("a", "f1"), 100)
	write(filepath.Join("a", "b", "f2"), 300)
	write(filepath.Join("a", "b", "big"), 4000)
	if err := os.MkdirAll(filepath.Join(root, "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func usageReset() {
	usageReg.Lock()
	for id, s := range usageReg.scans {
		s.stop("cancelled")
		delete(usageReg.scans, id)
	}
	usageReg.Unlock()
}

// usageWait waits for a scan to leave "running".
func usageWait(t *testing.T, s *usageScan) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.snapshotState(); st != "running" {
			// The completion goroutine sets the state after the workers ended.
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("scan still running")
	return ""
}

func usageNodeOf(t *testing.T, s *usageScan, p string) *usageNode {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.findLocked(p)
	if n == nil {
		t.Fatalf("no node for %s", p)
	}
	return n
}

func TestUsageScanAggregates(t *testing.T) {
	defer usageReset()
	root := usageTree(t)
	s, reused, err := usageStart(root, false)
	if err != nil || reused {
		t.Fatalf("start: %v reused=%v", err, reused)
	}
	if st := usageWait(t, s); st != "done" {
		t.Fatalf("state %s", st)
	}
	r := usageNodeOf(t, s, root)
	if r.size != 4450 || r.files != 4 || r.folders != 3 || !r.done {
		t.Fatalf("root: size=%d files=%d folders=%d done=%v", r.size, r.files, r.folders, r.done)
	}
	if r.ownSize != 50 || r.ownFiles != 1 {
		t.Fatalf("root loose files: %d bytes, %d files", r.ownSize, r.ownFiles)
	}
	a := usageNodeOf(t, s, filepath.Join(root, "a"))
	if a.size != 4400 || a.files != 3 || a.folders != 1 || a.ownSize != 100 {
		t.Fatalf("a: size=%d files=%d folders=%d own=%d", a.size, a.files, a.folders, a.ownSize)
	}
	if r.alloc < r.size {
		t.Fatalf("allocated %d below size %d", r.alloc, r.size)
	}
	if r.mtime <= 0 {
		t.Fatalf("no modification time")
	}

	// The command: children sorted by size, the loose files group, the files.
	d := &CommandDispatcher{}
	res, err := d.handleGetUsageChildren(AgentCommand{Payload: map[string]interface{}{
		"scanId": s.id, "paths": []interface{}{root, filepath.Join(root, "a"), filepath.Join(root, "nope")}, "files": true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]interface{})
	if m["state"] != "done" {
		t.Fatalf("state %v", m["state"])
	}
	nodes := m["nodes"].([]map[string]interface{})
	if len(nodes) != 3 || nodes[2]["found"] != false {
		t.Fatalf("nodes: %v", nodes)
	}
	kids := nodes[0]["children"].([]map[string]interface{})
	if len(kids) != 2 || kids[0]["name"] != "a" || kids[1]["name"] != "c" {
		t.Fatalf("children of root: %v", kids)
	}
	if kids[0]["size"].(int64) != 4400 || kids[0]["childCount"].(int) != 1 {
		t.Fatalf("a as a child: %v", kids[0])
	}
	g := nodes[0]["filesGroup"].(map[string]interface{})
	if g["count"].(int64) != 1 || g["size"].(int64) != 50 {
		t.Fatalf("root files group: %v", g)
	}
	af := nodes[1]["files"].([]map[string]interface{})
	if len(af) != 1 || af[0]["name"] != "f1" || af[0]["size"].(int64) != 100 {
		t.Fatalf("files of a: %v", af)
	}

	// The largest files of the scan, largest first.
	tr, err := d.handleGetUsageTopFiles(AgentCommand{Payload: map[string]interface{}{"scanId": s.id}})
	if err != nil {
		t.Fatal(err)
	}
	tf := tr.(map[string]interface{})["files"].([]map[string]interface{})
	if len(tf) != 4 || tf[0]["name"] != "big" || tf[0]["path"] != filepath.Join(root, "a", "b", "big") || tf[3]["name"] != "f0" {
		t.Fatalf("top files: %v", tf)
	}
}

// Partial results: a folder's own files and its subfolders show as soon as
// it is read; done climbs up only when the whole subtree is.
func TestUsageScanLivePartial(t *testing.T) {
	root := usageTree(t)
	s := newUsageScan(root, time.Now())
	s.scanDir(s.rootNode)
	r := s.rootNode
	if r.size != 50 || r.folders != 2 || r.done || len(s.queue) != 2 {
		t.Fatalf("after the root's listing: size=%d folders=%d done=%v queue=%d", r.size, r.folders, r.done, len(s.queue))
	}
	// Folder "a" (queue: LIFO, find it by name).
	var a *usageNode
	for _, c := range r.children {
		if c.name == "a" {
			a = c
		}
	}
	for i, q := range s.queue {
		if q == a {
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			break
		}
	}
	s.scanDir(a)
	if r.size != 150 || a.done || r.done {
		t.Fatalf("after a's listing: root %d, a done=%v", r.size, a.done)
	}
	for len(s.queue) > 0 {
		n := s.queue[len(s.queue)-1]
		s.queue = s.queue[:len(s.queue)-1]
		s.scanDir(n)
	}
	if r.size != 4450 || !a.done || !r.done {
		t.Fatalf("at the end: root %d, a done=%v, root done=%v", r.size, a.done, r.done)
	}
}

func TestUsageScanJoinRestartCancel(t *testing.T) {
	defer usageReset()
	root := usageTree(t)
	// Many folders: the scan is still running when it is joined.
	for i := 0; i < 300; i++ {
		_ = os.MkdirAll(filepath.Join(root, "many", fmt.Sprintf("d%03d", i), "x", "y"), 0o755)
	}
	s1, _, err := usageStart(root, false)
	if err != nil {
		t.Fatal(err)
	}
	s2, reused, err := usageStart(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if s1.snapshotState() == "running" && (!reused || s2 != s1) {
		t.Fatalf("a running scan of the same root is joined")
	}
	s3, reused, err := usageStart(root, true)
	if err != nil || reused || s3 == s1 {
		t.Fatalf("restart: a new scan (%v)", err)
	}
	if st := s1.snapshotState(); st != "cancelled" && st != "done" {
		t.Fatalf("the replaced scan: %s", st)
	}
	if _, err := usageGet(s1.id); err == nil {
		t.Fatalf("the replaced scan is forgotten")
	}
	d := &CommandDispatcher{}
	res, err := d.handleCancelUsageScan(AgentCommand{Payload: map[string]interface{}{"scanId": s3.id}})
	if err != nil {
		t.Fatal(err)
	}
	if st := res.(map[string]interface{})["state"]; st != "cancelled" && st != "done" {
		t.Fatalf("cancel: %v", st)
	}
	if st := usageWait(t, s3); st != "cancelled" && st != "done" {
		t.Fatalf("after cancel: %s", st)
	}
	// Its tree stays readable.
	if _, err := d.handleGetUsageChildren(AgentCommand{Payload: map[string]interface{}{"scanId": s3.id}}); err != nil {
		t.Fatalf("a cancelled scan stays readable: %v", err)
	}
}

func TestUsageScanCancelStopsWalk(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 200; i++ {
		_ = os.MkdirAll(filepath.Join(root, fmt.Sprintf("d%03d", i), "e"), 0o755)
	}
	s := newUsageScan(root, time.Now())
	s.stop("cancelled") // before any worker: nothing is walked
	s.begin()
	if st := usageWait(t, s); st != "cancelled" {
		t.Fatalf("state %s", st)
	}
	time.Sleep(20 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirsN != 0 || s.rootNode.done {
		t.Fatalf("a cancelled scan walks nothing: %d folders", s.dirsN)
	}
}

func TestUsageScanLimitsAndExpiry(t *testing.T) {
	defer usageReset()
	var roots []string
	for i := 0; i < 3; i++ {
		r := t.TempDir()
		for j := 0; j < 600; j++ {
			_ = os.MkdirAll(filepath.Join(r, fmt.Sprintf("d%04d", j)), 0o755)
		}
		roots = append(roots, r)
	}
	s1, _, err := usageStart(roots[0], false)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := usageStart(roots[1], false)
	if err != nil {
		t.Fatal(err)
	}
	if s1.snapshotState() == "running" && s2.snapshotState() == "running" {
		if _, _, err := usageStart(roots[2], false); err == nil || !strings.Contains(err.Error(), "already running") {
			t.Fatalf("a third running scan is refused: %v", err)
		}
	}
	usageWait(t, s1)
	usageWait(t, s2)
	// Not read for usageExpiry: stopped and forgotten.
	s1.mu.Lock()
	s1.lastRead = time.Now().Add(-usageExpiry - time.Minute)
	s1.mu.Unlock()
	usageReg.Lock()
	usageSweepLocked(time.Now())
	usageReg.Unlock()
	if _, err := usageGet(s1.id); err == nil {
		t.Fatalf("an expired scan is forgotten")
	}
	if _, err := usageGet(s2.id); err != nil {
		t.Fatalf("a scan read recently is kept: %v", err)
	}
}

func TestUsageScanRefusals(t *testing.T) {
	d := &CommandDispatcher{}
	root := usageTree(t)
	for _, p := range []string{"", "relative" + string(filepath.Separator) + "x", filepath.Join(root, "..", "x"), filepath.Join(root, "f0"), filepath.Join(root, "missing")} {
		if _, err := d.handleStartUsageScan(AgentCommand{Payload: map[string]interface{}{"path": p}}); err == nil {
			t.Errorf("start refused for %q", p)
		}
	}
	if _, err := d.handleGetUsageChildren(AgentCommand{Payload: map[string]interface{}{"scanId": "nope"}}); err == nil {
		t.Errorf("unknown scan refused")
	}
}

// Past the node cap, deeper folders are counted into their parent.
func TestUsageScanNodeCap(t *testing.T) {
	was := usageMaxNodes
	usageMaxNodes = 2
	defer func() { usageMaxNodes = was }()
	root := usageTree(t)
	s := newUsageScan(root, time.Now())
	s.begin()
	if st := usageWait(t, s); st != "done" {
		t.Fatalf("state %s", st)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rootNode
	if r.size != 4450 || r.files != 4 || r.folders != 3 || s.nodes > 2 {
		t.Fatalf("capped: size=%d files=%d folders=%d nodes=%d", r.size, r.files, r.folders, s.nodes)
	}
	trunc := r.truncated
	for _, c := range r.children {
		trunc = trunc || c.truncated
	}
	if !trunc {
		t.Fatalf("a capped tree says so (truncated)")
	}
}

// Privacy mode turned on stops the running scans.
func TestUsageStopAll(t *testing.T) {
	defer usageReset()
	root := t.TempDir()
	for j := 0; j < 1000; j++ {
		_ = os.MkdirAll(filepath.Join(root, fmt.Sprintf("d%04d", j), "x"), 0o755)
	}
	s, _, err := usageStart(root, false)
	if err != nil {
		t.Fatal(err)
	}
	usageStopAll()
	if st := usageWait(t, s); st != "cancelled" && st != "done" {
		t.Fatalf("state %s", st)
	}
	if !isBlockedByPrivacy("start_usage_scan") || !isBlockedByPrivacy("get_usage_children") ||
		!isBlockedByPrivacy("get_usage_top_files") || !isBlockedByPrivacy("cancel_usage_scan") ||
		privacyFeatureForCommand("get_usage_children") != "files" {
		t.Fatalf("the usage commands are file explorer commands for privacy mode")
	}
}

func TestListRootsVolumes(t *testing.T) {
	res, err := listRoots()
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]interface{})
	files := m["files"].([]FileInfo)
	if len(files) == 0 {
		t.Fatal("no roots")
	}
	if _, isWin := m["volumes"]; !isWin && filepath.Separator == '\\' {
		withSpace := 0
		for _, f := range files {
			if f.TotalBytes != nil && f.FreeBytes != nil {
				withSpace++
				if *f.TotalBytes <= 0 || *f.FreeBytes < 0 || *f.FreeBytes > *f.TotalBytes {
					t.Errorf("%s: total %d free %d", f.Path, *f.TotalBytes, *f.FreeBytes)
				}
			}
		}
		if withSpace == 0 {
			t.Errorf("no drive with its space: %+v", files)
		}
	}
}

// A real tree, measured (OBLIANCE_USAGE_MEASURE=<folder>): time, counts and
// the heap the scan holds once done.
func TestUsageScanMeasure(t *testing.T) {
	root := os.Getenv("OBLIANCE_USAGE_MEASURE")
	if root == "" {
		t.Skip("set OBLIANCE_USAGE_MEASURE to a folder to measure a scan")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	s := newUsageScan(root, start)
	s.begin()
	for s.snapshotState() == "running" && time.Since(start) < 15*time.Minute {
		time.Sleep(50 * time.Millisecond)
	}
	st := s.snapshotState()
	took := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&after)
	s.mu.Lock()
	t.Logf("%s: %s in %v, %d files, %d folders, %d nodes, %d bytes (%d allocated), %d errors, %d skipped, heap held %.1f MB",
		root, st, took, s.filesN, s.dirsN, s.nodes, s.bytesN, s.allocN, s.errorsN, s.skippedN, float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/1e6)
	s.mu.Unlock()
	runtime.KeepAlive(s)
}

// A deletion from the explorer reaches the scans at once.
func TestUsageScanForgetOnDelete(t *testing.T) {
	defer usageReset()
	root := usageTree(t)
	s, _, err := usageStart(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if st := usageWait(t, s); st != "done" {
		t.Fatalf("state %s", st)
	}
	d := &CommandDispatcher{}
	if _, err := d.handleDeleteFile(AgentCommand{Payload: map[string]interface{}{"path": filepath.Join(root, "a", "b"), "recursive": true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.handleDeleteFile(AgentCommand{Payload: map[string]interface{}{"path": filepath.Join(root, "f0")}}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	r, a := s.rootNode, s.findLocked(filepath.Join(root, "a"))
	gotTop := len(s.top)
	s.mu.Unlock()
	if r.size != 100 || r.files != 1 || r.folders != 2 || r.ownFiles != 0 || a.size != 100 || len(a.children) != 0 {
		t.Fatalf("after the deletions: root size=%d files=%d folders=%d own=%d, a size=%d kids=%d", r.size, r.files, r.folders, r.ownFiles, a.size, len(a.children))
	}
	if gotTop != 1 {
		t.Fatalf("largest files after the deletions: %d, want 1 (f1)", gotTop)
	}
}

// At most usageMaxRunning running scans; one nobody read for
// usageOrphanAfter gives its place.
func TestUsageScanRunningCapAndOrphan(t *testing.T) {
	defer usageReset()
	now := time.Now()
	a := newUsageScan(t.TempDir(), now) // never begun: running forever
	b := newUsageScan(t.TempDir(), now)
	usageReg.Lock()
	usageReg.scans[a.id] = a
	usageReg.scans[b.id] = b
	usageReg.Unlock()
	if _, _, err := usageStart(t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("a third running scan is refused: %v", err)
	}
	a.mu.Lock()
	a.lastRead = now.Add(-usageOrphanAfter - time.Second)
	a.mu.Unlock()
	s, _, err := usageStart(t.TempDir(), false)
	if err != nil {
		t.Fatalf("an orphan gives its place: %v", err)
	}
	usageWait(t, s)
	if a.snapshotState() != "cancelled" || b.snapshotState() != "running" {
		t.Fatalf("the orphan is stopped, the other kept: %s %s", a.snapshotState(), b.snapshotState())
	}
}
