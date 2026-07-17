module code

// stdlib_similar_assign_test.v — unit coverage for the `similar` module's
// optimal-assignment solver (graded join `selection: :optimal`), see
// stdlib_similar_assign.v. Includes a brute-force permutation cross-check.

fn similar_test_close(a f64, b f64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// --- brute-force reference (square matrices, all scores > 0) ---

struct SimilarBf {
mut:
	best_total f64 = -1.0
	best       []int
	count      int
}

fn (mut s SimilarBf) recurse(score [][]f64, row int, mut used []bool, mut cur []int, total f64) {
	n := score.len
	if row == n {
		if total > s.best_total + 1e-12 {
			s.best_total = total
			s.best = cur.clone()
			s.count = 1
		} else if total > s.best_total - 1e-12 {
			s.count++
		}
		return
	}
	for j in 0 .. n {
		if !used[j] {
			used[j] = true
			cur[row] = j
			s.recurse(score, row + 1, mut used, mut cur, total + score[row][j])
			used[j] = false
		}
	}
}

fn similar_brute_force(score [][]f64) ([]int, f64, int) {
	n := score.len
	mut s := SimilarBf{}
	mut used := []bool{len: n}
	mut cur := []int{len: n}
	s.recurse(score, 0, mut used, mut cur, 0.0)
	return s.best, s.best_total, s.count
}

// --- (a) square 3x3 with known optimal ---

fn test_square_3x3_known_optimal() {
	score := [
		[0.7, 0.9, 0.1],
		[0.8, 0.2, 0.3],
		[0.4, 0.5, 0.6],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [1, 0, 2]
	assert similar_test_close(similar_assignment_total(score, assign), 2.3)
}

// --- (b) rectangular: more columns than rows, and the reverse ---

fn test_rect_2x4_more_columns() {
	score := [
		[0.1, 0.9, 0.2, 0.3],
		[0.8, 0.95, 0.1, 0.2],
	]
	assign := similar_optimal_assignment(score)
	// Greedy would give row1 the 0.95 and strand row0 on 0.3 (total 1.25);
	// the optimum is 0.9 + 0.8 = 1.7.
	assert assign == [1, 0]
	assert similar_test_close(similar_assignment_total(score, assign), 1.7)
}

fn test_rect_4x2_more_rows() {
	score := [
		[0.2, 0.3],
		[0.9, 0.1],
		[0.4, 0.8],
		[0.5, 0.6],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [-1, 0, 1, -1]
	assert similar_test_close(similar_assignment_total(score, assign), 1.7)
}

// --- (c) tie-breaking determinism: input order wins ---

fn test_tie_break_input_order() {
	// Both the diagonal and the anti-diagonal total 1.0; the solver must
	// pick lowest row index, then lowest column index: row0->col0.
	score := [
		[0.5, 0.5],
		[0.5, 0.5],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [0, 1]
	assert similar_test_close(similar_assignment_total(score, assign), 1.0)
}

fn test_tie_break_stable_across_repeats() {
	score := [
		[0.4, 0.4, 0.4],
		[0.4, 0.4, 0.4],
		[0.4, 0.4, 0.4],
	]
	first := similar_optimal_assignment(score)
	assert first == [0, 1, 2]
	for _ in 0 .. 10 {
		assert similar_optimal_assignment(score) == first
	}
}

// --- (d) greedy-vs-optimal ---

fn test_greedy_suboptimal_hungarian_optimal() {
	score := [
		[0.9, 0.8],
		[0.85, 0.1],
	]
	assign := similar_optimal_assignment(score)
	// Greedy per-row best: row0->col0 (0.9) + row1->col1 (0.1) = 1.0.
	// Optimal: row0->col1 (0.8) + row1->col0 (0.85) = 1.65.
	assert assign == [1, 0]
	assert similar_test_close(similar_assignment_total(score, assign), 1.65)
}

// --- (e) zero-score pairs are never assigned ---

fn test_zero_score_pairs_unassigned() {
	score := [
		[0.0, 0.0],
		[0.5, 0.0],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [-1, 0]
	assert similar_test_close(similar_assignment_total(score, assign), 0.5)
}

fn test_all_zero_matrix_no_assignments() {
	score := [
		[0.0, 0.0, 0.0],
		[0.0, 0.0, 0.0],
		[0.0, 0.0, 0.0],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [-1, -1, -1]
	assert similar_test_close(similar_assignment_total(score, assign), 0.0)
}

fn test_zero_column_row_mix() {
	score := [
		[0.7, 0.0],
		[0.0, 0.0],
	]
	assign := similar_optimal_assignment(score)
	assert assign == [0, -1]
	assert similar_test_close(similar_assignment_total(score, assign), 0.7)
}

// --- (f) empty and 1x1 ---

fn test_empty_matrix() {
	score := [][]f64{}
	assign := similar_optimal_assignment(score)
	assert assign.len == 0
	assert similar_test_close(similar_assignment_total(score, assign), 0.0)
}

fn test_rows_with_no_columns() {
	score := [[]f64{}, []f64{}]
	assign := similar_optimal_assignment(score)
	assert assign == [-1, -1]
	assert similar_test_close(similar_assignment_total(score, assign), 0.0)
}

fn test_single_cell_nonzero() {
	score := [[0.7]]
	assign := similar_optimal_assignment(score)
	assert assign == [0]
	assert similar_test_close(similar_assignment_total(score, assign), 0.7)
}

fn test_single_cell_zero() {
	score := [[0.0]]
	assign := similar_optimal_assignment(score)
	assert assign == [-1]
	assert similar_test_close(similar_assignment_total(score, assign), 0.0)
}

// --- (g) 6x6 hardcoded matrix vs brute-force permutation enumeration ---

fn test_6x6_matches_brute_force() {
	score := [
		[0.62, 0.17, 0.83, 0.45, 0.29, 0.91],
		[0.34, 0.78, 0.12, 0.66, 0.53, 0.21],
		[0.88, 0.41, 0.57, 0.23, 0.74, 0.36],
		[0.19, 0.65, 0.32, 0.87, 0.48, 0.55],
		[0.73, 0.28, 0.94, 0.16, 0.61, 0.42],
		[0.51, 0.37, 0.26, 0.69, 0.85, 0.14],
	]
	assign := similar_optimal_assignment(score)
	bf_assign, bf_total, bf_count := similar_brute_force(score)
	total := similar_assignment_total(score, assign)
	assert similar_test_close(total, bf_total)
	if bf_count == 1 {
		assert assign == bf_assign
	}
	// Sanity: every row assigned, no column reused.
	mut seen := []bool{len: 6}
	for j in assign {
		assert j >= 0 && j < 6
		assert !seen[j]
		seen[j] = true
	}
}
