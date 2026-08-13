package relayselection

import (
	"errors"
	"sort"
	"time"
)

const (
	MaximumRegions = 32
)

var ErrInvalid = errors.New("invalid relay selection")

type Sample struct {
	Region string
	RTT    time.Duration
}

type Vector struct {
	Generation         uint64
	ObservedAt         time.Time
	Samples            []Sample
	RelaySuccessRegion string
	RelaySuccessAt     time.Time
}

type Node struct {
	Region string
	Value  any
}

type scoredNode struct {
	node Node
	rtt  time.Duration
}

type State struct {
	Current                  string
	ClientGeneration         uint64
	ClientObservedAt         time.Time
	Candidate                string
	CandidateFirstObservedAt time.Time
	CandidateLastObservedAt  time.Time
	CandidateSamples         uint8
}

func Select(now time.Time, previous State, client, host Vector, nodes []Node) (Node, State, error) {
	if now.IsZero() || len(nodes) == 0 || len(nodes) > MaximumRegions || !freshVector(now, client) || !freshVector(now, host) || !validState(previous) {
		return Node{}, State{}, ErrInvalid
	}
	clientRTT, err := vectorMap(client)
	if err != nil {
		return Node{}, State{}, err
	}
	hostRTT, err := vectorMap(host)
	if err != nil {
		return Node{}, State{}, err
	}
	if !previous.ClientObservedAt.IsZero() && (client.ObservedAt.Before(previous.ClientObservedAt) || client.ObservedAt.Equal(previous.ClientObservedAt) && client.Generation <= previous.ClientGeneration) {
		return Node{}, State{}, ErrInvalid
	}
	next := previous
	next.ClientGeneration, next.ClientObservedAt = client.Generation, client.ObservedAt
	scores := make([]scoredNode, 0, len(nodes))
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		left, leftOK := clientRTT[node.Region]
		right, rightOK := hostRTT[node.Region]
		if !validRegion(node.Region) || seen[node.Region] || !leftOK || !rightOK || left > time.Duration(1<<63-1)-right {
			continue
		}
		seen[node.Region] = true
		scores = append(scores, scoredNode{node: node, rtt: left + right})
	}
	// A recently authenticated relay success keeps the selected, healthy region
	// eligible when a probe scan temporarily omits it. It does not invent a
	// score, so it cannot trigger or bypass the sustained switch rule.
	if current := next.Current; current != "" {
		if _, ok := findScore(scores, current); !ok && recentSuccess(current, now, client, host) {
			for _, node := range nodes {
				if node.Region == current {
					reset(&next)
					return node, next, nil
				}
			}
		}
	}
	if len(scores) == 0 {
		return Node{}, State{}, ErrInvalid
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].rtt == scores[j].rtt {
			return scores[i].node.Region < scores[j].node.Region
		}
		return scores[i].rtt < scores[j].rtt
	})
	best := scores[0]
	currentScore, currentOK := findScore(scores, next.Current)
	if next.Current == "" || !currentOK {
		next.Current = best.node.Region
		reset(&next)
		return best.node, next, nil
	}
	if best.node.Region == next.Current || !qualifies(currentScore.rtt, best.rtt) {
		reset(&next)
		return currentScore.node, next, nil
	}
	observed := client.ObservedAt
	if host.ObservedAt.Before(observed) {
		observed = host.ObservedAt
	}
	if next.Candidate != best.node.Region {
		next.Candidate, next.CandidateFirstObservedAt, next.CandidateLastObservedAt, next.CandidateSamples = best.node.Region, observed, observed, 1
		return currentScore.node, next, nil
	}
	if observed.Sub(next.CandidateLastObservedAt) < 3*time.Second {
		return currentScore.node, next, nil
	}
	next.CandidateLastObservedAt, next.CandidateSamples = observed, next.CandidateSamples+1
	if next.CandidateSamples < 3 || next.CandidateLastObservedAt.Sub(next.CandidateFirstObservedAt) < 10*time.Second {
		return currentScore.node, next, nil
	}
	next.Current = best.node.Region
	reset(&next)
	return best.node, next, nil
}

func recentSuccess(region string, now time.Time, vectors ...Vector) bool {
	for _, vector := range vectors {
		if vector.RelaySuccessRegion == region && !vector.RelaySuccessAt.IsZero() && !vector.RelaySuccessAt.After(now) && now.Sub(vector.RelaySuccessAt) <= 30*time.Second {
			return true
		}
	}
	return false
}

func validState(value State) bool {
	if value.Current != "" && !validRegion(value.Current) || value.Candidate != "" && !validRegion(value.Candidate) || value.CandidateSamples > 16 {
		return false
	}
	if value.ClientGeneration == 0 != value.ClientObservedAt.IsZero() {
		return false
	}
	return value.Candidate == "" == (value.CandidateSamples == 0) && value.Candidate == "" == value.CandidateFirstObservedAt.IsZero() && value.Candidate == "" == value.CandidateLastObservedAt.IsZero()
}

func freshVector(now time.Time, vector Vector) bool {
	if vector.Generation == 0 || vector.ObservedAt.IsZero() || vector.ObservedAt.After(now.Add(30*time.Second)) || now.Sub(vector.ObservedAt) > 5*time.Minute {
		return false
	}
	return vector.RelaySuccessRegion == "" && vector.RelaySuccessAt.IsZero() || validRegion(vector.RelaySuccessRegion) && !vector.RelaySuccessAt.IsZero() && !vector.RelaySuccessAt.After(vector.ObservedAt) && vector.ObservedAt.Sub(vector.RelaySuccessAt) <= 30*time.Second
}

func vectorMap(vector Vector) (map[string]time.Duration, error) {
	if len(vector.Samples) == 0 || len(vector.Samples) > MaximumRegions {
		return nil, ErrInvalid
	}
	result := make(map[string]time.Duration, len(vector.Samples))
	for _, sample := range vector.Samples {
		if !validRegion(sample.Region) || sample.RTT <= 0 || sample.RTT > time.Minute || result[sample.Region] != 0 {
			return nil, ErrInvalid
		}
		result[sample.Region] = sample.RTT
	}
	return result, nil
}

func validRegion(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}

func findScore(scores []scoredNode, region string) (scoredNode, bool) {
	for _, score := range scores {
		if score.node.Region == region {
			return score, true
		}
	}
	return scoredNode{}, false
}

func qualifies(current, candidate time.Duration) bool {
	return candidate < current && current-candidate >= 10*time.Millisecond && uint64(current-candidate)*100 >= uint64(current)*15
}

func reset(s *State) {
	s.Candidate, s.CandidateFirstObservedAt, s.CandidateLastObservedAt, s.CandidateSamples = "", time.Time{}, time.Time{}, 0
}
