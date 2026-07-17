module code

// stdlib_similar_assign.v — rectangular Hungarian (Kuhn–Munkres) assignment
// solver for the `similar` module's graded join `selection: :optimal`:
// globally optimal 1:1 record linkage maximizing total similarity score.
//
// Algorithm: O(n³) Jonker–Volgenant-style shortest augmenting path with row
// and column potentials, run on a square matrix padded with zero-score dummy
// rows/columns. Scores are maximized by negating into costs. Deterministic:
// rows are processed in input order and columns scanned in ascending index
// with strict-less comparisons, so ties resolve to the lowest row index,
// then the lowest column index. No randomization, no map iteration.
//
// A score of exactly 0.0 means "no viable link": such pairs are never
// reported as assigned (the row is left at -1), which also makes the dummy
// padding invisible to callers.

const similar_assign_inf = 1e30

// similar_optimal_assignment returns, for each row of `score`, the column
// assigned to it, or -1 if the row is unassigned. Rows are left records,
// columns are right records, values are similarity scores in [0,1]. The
// matrix may be rectangular; each row and column is used at most once and
// the total assigned score is maximal.
fn similar_optimal_assignment(score [][]f64) []int {
	rows := score.len
	if rows == 0 {
		return []int{}
	}
	cols := score[0].len
	if cols == 0 {
		return []int{len: rows, init: -1}
	}
	nn := if rows > cols { rows } else { cols }
	// Pad to nn×nn; dummy cells carry score 0 (cost 0), real cells cost
	// the negated score so that minimizing cost maximizes total score.
	mut cost := [][]f64{len: nn, init: []f64{len: nn, init: 0.0}}
	for i in 0 .. rows {
		for j in 0 .. cols {
			cost[i][j] = -score[i][j]
		}
	}
	// Shortest-augmenting-path Hungarian with potentials. Index nn plays
	// the role of the virtual row/column of the classic formulation.
	mut u := []f64{len: nn + 1} // row potentials
	mut v := []f64{len: nn + 1} // column potentials
	mut p := []int{len: nn + 1, init: nn} // p[j] = row matched to column j (nn = none)
	mut way := []int{len: nn + 1}
	for i in 0 .. nn {
		p[nn] = i
		mut j0 := nn
		mut minv := []f64{len: nn + 1, init: similar_assign_inf}
		mut used := []bool{len: nn + 1}
		for {
			used[j0] = true
			i0 := p[j0]
			mut delta := similar_assign_inf
			mut j1 := -1
			for j in 0 .. nn {
				if !used[j] {
					cur := cost[i0][j] - u[i0] - v[j]
					if cur < minv[j] {
						minv[j] = cur
						way[j] = j0
					}
					if minv[j] < delta {
						delta = minv[j]
						j1 = j
					}
				}
			}
			for j in 0 .. nn + 1 {
				if used[j] {
					u[p[j]] += delta
					v[j] -= delta
				} else {
					minv[j] -= delta
				}
			}
			j0 = j1
			if p[j0] == nn {
				break
			}
		}
		// Augment along the recorded alternating path.
		for {
			j1 := way[j0]
			p[j0] = p[j1]
			j0 = j1
			if j0 == nn {
				break
			}
		}
	}
	mut assign := []int{len: rows, init: -1}
	for j in 0 .. nn {
		i := p[j]
		if i < rows && j < cols && score[i][j] != 0.0 {
			assign[i] = j
		}
	}
	return assign
}

// similar_assignment_total sums the scores of the assigned pairs in `assign`
// (as produced by similar_optimal_assignment); unassigned rows contribute 0.
fn similar_assignment_total(score [][]f64, assign []int) f64 {
	mut total := 0.0
	for i, j in assign {
		if j >= 0 && i < score.len && j < score[i].len {
			total += score[i][j]
		}
	}
	return total
}
