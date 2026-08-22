package relayselection

import (
	"testing"
	"time"
)

func TestSelectUsesTwoEndedScoreAndPersistedSustainedSwitch(t *testing.T) {
	base := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	nodes := []Node{{Region: "fsn1", Value: "fsn"}, {Region: "hel1", Value: "hel"}}
	state := State{}
	selectRegion := func(generation uint64, at time.Time, fsn, hel time.Duration) string {
		client := Vector{Generation: generation, ObservedAt: at, Samples: []Sample{{Region: "fsn1", RTT: fsn / 2}, {Region: "hel1", RTT: hel / 2}}}
		host := Vector{Generation: 1, ObservedAt: at, Samples: []Sample{{Region: "fsn1", RTT: fsn - fsn/2}, {Region: "hel1", RTT: hel - hel/2}}}
		node, next, err := Select(at.Add(time.Second), state, client, host, nodes)
		if err != nil {
			t.Fatal(err)
		}
		state = next
		return node.Region
	}
	if got := selectRegion(1, base, 80*time.Millisecond, 120*time.Millisecond); got != "fsn1" {
		t.Fatal(got)
	}
	if got := selectRegion(2, base.Add(time.Second), 80*time.Millisecond, 50*time.Millisecond); got != "fsn1" {
		t.Fatal(got)
	}
	if got := selectRegion(3, base.Add(4*time.Second), 80*time.Millisecond, 50*time.Millisecond); got != "fsn1" {
		t.Fatal(got)
	}
	if got := selectRegion(4, base.Add(11*time.Second), 80*time.Millisecond, 50*time.Millisecond); got != "hel1" {
		t.Fatal(got)
	}
}

func TestSelectImmediatelyReplacesUnavailableCurrentAndKeepsReorderedObservationsAdvisory(t *testing.T) {
	now := time.Now().UTC()
	vector := func(generation uint64, at time.Time) Vector {
		return Vector{Generation: generation, ObservedAt: at, Samples: []Sample{{Region: "hel1", RTT: 20 * time.Millisecond}}}
	}
	node, state, err := Select(now, State{Current: "fsn1"}, vector(8, now), vector(1, now), []Node{{Region: "hel1"}})
	if err != nil || node.Region != "hel1" {
		t.Fatalf("node=%#v err=%v", node, err)
	}
	repeated, unchanged, err := Select(now, state, vector(8, now), vector(1, now), []Node{{Region: "hel1"}})
	if err != nil || repeated.Region != "hel1" || unchanged != state {
		t.Fatalf("same vector node=%#v state=%#v err=%v", repeated, unchanged, err)
	}
	reordered, unchanged, err := Select(now, state, vector(7, now.Add(-time.Millisecond)), vector(1, now), []Node{{Region: "hel1"}})
	if err != nil || reordered.Region != "hel1" || unchanged != state {
		t.Fatalf("reordered vector node=%#v state=%#v err=%v", reordered, unchanged, err)
	}
	if _, _, err := Select(now.Add(time.Second), state, vector(1, now.Add(time.Second)), vector(1, now.Add(time.Second)), []Node{{Region: "hel1"}}); err != nil {
		t.Fatalf("new process vector counter was not accepted: %v", err)
	}
}

func TestSelectRoutesStaleObservationWhenPreviousNodeDisappeared(t *testing.T) {
	now := time.Date(2026, 8, 22, 22, 23, 57, 0, time.UTC)
	previous := State{Current: "bom1", ClientGeneration: 7, ClientObservedAt: now}
	client := Vector{Generation: 6, ObservedAt: now.Add(-time.Millisecond), Samples: []Sample{{Region: "hel1", RTT: 30 * time.Millisecond}}}
	host := Vector{Generation: 3, ObservedAt: now, Samples: []Sample{{Region: "hel1", RTT: 20 * time.Millisecond}}}
	node, next, err := Select(now, previous, client, host, []Node{{Region: "hel1", Value: "helsinki"}})
	if err != nil || node.Region != "hel1" || next != previous {
		t.Fatalf("node=%#v state=%#v err=%v", node, next, err)
	}
}

func TestSelectAcceptsConcurrentObservationsInNetworkArrivalOrder(t *testing.T) {
	base := time.Date(2026, 8, 22, 22, 23, 57, 0, time.UTC)
	nodes := []Node{{Region: "bom1", Value: "mumbai"}, {Region: "hel1", Value: "helsinki"}}
	host := Vector{Generation: 3, ObservedAt: base, Samples: []Sample{{Region: "bom1", RTT: 20 * time.Millisecond}, {Region: "hel1", RTT: 40 * time.Millisecond}}}
	client := func(generation uint64, observedAt time.Time) Vector {
		return Vector{Generation: generation, ObservedAt: observedAt, Samples: []Sample{{Region: "bom1", RTT: 30 * time.Millisecond}, {Region: "hel1", RTT: 20 * time.Millisecond}}}
	}
	_, state, err := Select(base, State{}, client(5, base), host, nodes)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err = Select(base.Add(2*time.Millisecond), state, client(7, base.Add(2*time.Millisecond)), host, nodes)
	if err != nil {
		t.Fatal(err)
	}
	want := state
	node, state, err := Select(base.Add(3*time.Millisecond), state, client(6, base.Add(time.Millisecond)), host, nodes)
	if err != nil || node.Region != want.Current || state != want {
		t.Fatalf("reordered concurrent observation node=%#v state=%#v want=%#v err=%v", node, state, want, err)
	}
}

func TestSelectKeepsRecentlySuccessfulCurrentWhenScanOmitsIt(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 30, 0, time.UTC)
	client := Vector{Generation: 2, ObservedAt: now, Samples: []Sample{{Region: "hel1", RTT: 20 * time.Millisecond}}, RelaySuccessRegion: "fsn1", RelaySuccessAt: now.Add(-10 * time.Second)}
	host := Vector{Generation: 2, ObservedAt: now, Samples: []Sample{{Region: "hel1", RTT: 20 * time.Millisecond}}}
	node, next, err := Select(now, State{Current: "fsn1", ClientGeneration: 1, ClientObservedAt: now.Add(-time.Minute)}, client, host, []Node{{Region: "fsn1", Value: "fsn"}, {Region: "hel1", Value: "hel"}})
	if err != nil || node.Region != "fsn1" || next.Current != "fsn1" {
		t.Fatalf("node=%#v next=%#v err=%v", node, next, err)
	}
	client.Generation, client.ObservedAt, client.RelaySuccessRegion, client.RelaySuccessAt = 3, now.Add(time.Second), "", time.Time{}
	host.ObservedAt = now.Add(time.Second)
	node, _, err = Select(now.Add(time.Second), next, client, host, []Node{{Region: "fsn1", Value: "fsn"}, {Region: "hel1", Value: "hel"}})
	if err != nil || node.Region != "hel1" {
		t.Fatalf("expired success node=%#v err=%v", node, err)
	}
}
