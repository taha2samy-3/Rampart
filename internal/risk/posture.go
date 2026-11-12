package risk

// CalculatePostureScore computes the 0-1000 posture score (higher is better)
// from open finding counts, asset count, SLA adherence, and coverage gaps per docs/06 section 2.
func CalculatePostureScore(open map[string]int, assetCount int, slaAdherence *float64, coverageGaps int) int {
	if len(open) == 0 {
		return 1000
	}
	totalOpen := open["critical"] + open["high"] + open["medium"] + open["low"]
	if totalOpen == 0 {
		return 1000
	}

	assets := assetCount
	if assets < 1 {
		assets = 1
	}

	// Weighted open risk points: critical 250, high 100, medium 30, low 5
	weightedRisk := open["critical"]*250 + open["high"]*100 + open["medium"]*30 + open["low"]*5

	// Normalize by asset count, bounded at 750 points penalty
	riskPenalty := weightedRisk / assets
	if riskPenalty > 750 {
		riskPenalty = 750
	}

	// SLA adherence modifier: if adherence is below 100%, up to 150 points penalty
	slaPenalty := 0
	if slaAdherence != nil {
		adherence := *slaAdherence
		if adherence < 1.0 {
			slaPenalty = int((1.0 - adherence) * 150.0)
		}
	}

	// Coverage modifier: coverage gaps penalize up to 100 points (20 pts per gap)
	covPenalty := coverageGaps * 20
	if covPenalty > 100 {
		covPenalty = 100
	}

	score := 1000 - riskPenalty - slaPenalty - covPenalty
	if score < 0 {
		score = 0
	}
	if score > 1000 {
		score = 1000
	}
	return score
}
