module code

import cx

// ── Cooperative task scheduler (Phase 3.7 commit B) ─────────────────────────
//
// Drives the fixture-only `[?test-concurrent :tasks (…)]` helper per
// `conformance/code.txt §Format` and the scheduler contract
// alluded to by `spec/code.md §10.2.6` (`[?bulkhead]` wait-for-
// slot semantics). The scheduler runs at most one task at a time —
// strict cooperative single-runner — but uses real V threads + per-
// task rendezvous channels to model task interleaving:
//
//   * Each task body spawns into its own V thread.
//   * Each thread blocks on `run_gate` until the scheduler signals it.
//   * Each thread sends on `yield_gate` whenever it would block:
//     `.sleep` (mock-clock yield), `.bulkhead_queue` (bulkhead-full
//     queue-wait), `.done` (terminal — body completed normally or with
//     an `[err]` value or a hard `EvalError`).
//   * The scheduler reads `yield_gate`, decides what to do, and
//     signals exactly one task to run next. Because signal exchange
//     is synchronous, no two task bodies ever execute concurrently —
//     so `MatchEnv.state` mutations (channels, bulkhead state, mock
//     clock) need no locking even though the bookkeeping involves
//     several pointer-shared maps.
//
// The substrate matches the user-selected option (a) on the 2026-05-21
// design poll: mock-clock-driven cooperative scheduler, no real-time
// dependence, deterministic ordering by source position when multiple
// tasks become simultaneously runnable.
//
// Mock-clock advance: when no task is ready (all sleeping / queued),
// the scheduler advances `now_ns` to the earliest `sleep_until_ns`,
// wakes the corresponding task, and continues. A task that has
// queued for a bulkhead is granted its slot eagerly inside the
// settle phase as soon as a slot frees — no clock advance needed.

pub enum TaskYieldKind {
	sleep
	bulkhead_queue
	done
}

// TaskRecord carries one task's scheduler state. The `body` AST is
// shared (the task does not mutate it). `bindings_snapshot` is the
// parent env's bindings at the moment `[?test-concurrent]` froze the
// task. `state` cycles through 'pending' → 'running' / 'sleeping' /
// 'bulkhead_queued' → 'done'. Pointers are stable across the
// scheduler driver's lifetime; the task thread holds one and the
// scheduler holds another.
@[heap]
pub struct TaskRecord {
pub mut:
	id                int
	body              cx.ProgramNode
	bindings_snapshot map[string]cx.Node
	state             string
	result            cx.Node
	err_message       string
	sleep_until_ns    i64
	queued_bulkhead   string
	completion_idx    int = -1
	run_gate          chan bool
	yield_gate        chan TaskYieldKind
}

// run_task_thread is the V-thread body for one cooperative task. It
// blocks on `run_gate` for the initial go-ahead, evaluates the body
// against a freshly-constructed MatchEnv backed by the shared
// ProgramState pointer, and sends `.done` on `yield_gate` when the
// body terminates (with the result, an `[err]` value, or a hard
// EvalError captured in `err_message`). Sleep / bulkhead-queue yields
// happen inline inside `eval_node` via `task_yield`.
pub fn run_task_thread(t_ptr &TaskRecord, state_ptr &ProgramState,
                         closures_snapshot map[string]Closure) {
	mut t := unsafe { t_ptr }
	_ := <-t.run_gate
	mut env := MatchEnv{
		bindings:     t.bindings_snapshot.clone()
		closures:     closures_snapshot.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-task frame pool (#36); thread-local
	}
	result := eval_node(t.body, mut env) or {
		t.err_message = err.msg()
		t.yield_gate <- TaskYieldKind.done
		return
	}
	t.result = result
	t.yield_gate <- TaskYieldKind.done
}

// task_yield is the entry-point for any directive (eval_sleep,
// eval_bulkhead) that needs to suspend the current task. It blocks
// the task thread until the scheduler re-signals `run_gate`.
fn task_yield(t_ptr &TaskRecord, kind TaskYieldKind) {
	mut t := unsafe { t_ptr }
	t.yield_gate <- kind
	_ := <-t.run_gate
}

// drive_scheduler runs the cooperative scheduler loop until every
// task in `tasks` reaches the 'done' state. Returns each task's
// result in completion order. The caller (eval_test_concurrent)
// builds the `(r1, r2, …)` sequence node from this slice.
pub fn drive_scheduler(mut tasks []&TaskRecord, mut env MatchEnv) []cx.Node {
	mut completed := 0
	mut completion_log := []int{}
	for completed < tasks.len {
		settle(mut tasks, mut env)
		picked := pick_runnable(tasks)
		if picked < 0 {
			if !advance_clock_to_next_wake(mut tasks, mut env) {
				break
			}
			continue
		}
		mut t := tasks[picked]
		t.state = 'running'
		env.state.current_task_set(t.id)
		t.run_gate <- true
		kind := <-t.yield_gate
		env.state.current_task_set(0)
		match kind {
			.done {
				t.state = 'done'
				t.completion_idx = completion_log.len
				completion_log << t.id
				completed++
			}
			.sleep { t.state = 'sleeping' }
			.bulkhead_queue { t.state = 'bulkhead_queued' }
		}
	}
	mut out := []cx.Node{cap: completion_log.len}
	for id in completion_log {
		for t in tasks {
			if t.id != id { continue }
			if t.err_message != '' {
				out << err_from_message(t.err_message)
			} else {
				out << t.result
			}
			break
		}
	}
	return out
}

// settle wakes sleeping tasks whose target time has arrived and
// grants bulkhead slots to queued waiters wherever capacity allows.
// The settle phase is idempotent and runs before every pick to
// catch state changes the most recently completed task may have
// caused (e.g. releasing a slot decrements in_flight; a queued
// waiter on the same name becomes grantable).
fn settle(mut tasks []&TaskRecord, mut env MatchEnv) {
	now := env.state.clock_now()
	for mut t in tasks {
		if t.state == 'sleeping' && now >= t.sleep_until_ns {
			t.state = 'ready'
		}
	}
	// Snapshot the bulkhead map under the read lock; we mutate via the
	// per-entry write helper so concurrent worker `bh_set` calls don't
	// race with the iteration.
	snapshot := env.state.bh_snapshot_all()
	for name, _ in snapshot {
		mut rec := env.state.bh_get(name)
		for rec.in_flight < rec.max_concurrent && rec.wait_queue.len > 0 {
			granted_id := rec.wait_queue[0]
			rec.wait_queue.delete(0)
			rec.queued--
			rec.in_flight++
			env.state.bh_set(name, rec)
			for mut t in tasks {
				if t.id == granted_id && t.state == 'bulkhead_queued'
				   && t.queued_bulkhead == name {
					t.state = 'ready'
					t.queued_bulkhead = ''
					break
				}
			}
			rec = env.state.bh_get(name)
		}
	}
}

// pick_runnable returns the source-position-earliest task whose state
// is 'pending' or 'ready', or -1 if none. Source-position ordering on
// ties matches spec/code.md §10.4.7's "uniform-random tie-break
// degenerates to source order" rule under the single-runner substrate.
fn pick_runnable(tasks []&TaskRecord) int {
	for i, t in tasks {
		if t.state == 'pending' || t.state == 'ready' {
			return i
		}
	}
	return -1
}

// advance_clock_to_next_wake bumps `now_ns` to the smallest pending
// sleep target and marks the matching task ready. Returns false when
// no task is sleeping (the scheduler is genuinely deadlocked — all
// remaining tasks are bulkhead-queued on names whose slots no other
// task will release; cooperative deadlock is fatal but rare in the
// fixture battery).
fn advance_clock_to_next_wake(mut tasks []&TaskRecord, mut env MatchEnv) bool {
	mut earliest := i64(-1)
	for t in tasks {
		if t.state == 'sleeping' {
			if earliest < 0 || t.sleep_until_ns < earliest {
				earliest = t.sleep_until_ns
			}
		}
	}
	if earliest < 0 {
		return false
	}
	now := env.state.clock_now()
	if earliest > now {
		env.state.clock_set(earliest)
	}
	now2 := env.state.clock_now()
	for mut t in tasks {
		if t.state == 'sleeping' && t.sleep_until_ns <= now2 {
			t.state = 'ready'
		}
	}
	return true
}

// err_from_message wraps a raw EvalError message into the canonical
// failure outcome draft-3 `[result status=err inner=MSG]`
// (the scalar message → attribute). Hard EvalErrors raised inside a
// task body surface here when run_task_thread captures them; presenting
// them as a value lets [?test-concurrent] return a uniform sequence
// shape without distinguishing soft (err-value) vs hard (EvalError)
// failures at the driver level.
fn err_from_message(msg string) cx.Node {
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('err') },
			cx.Attribute{ name: 'inner', value: cx.ScalarValue(msg) },
		]
	}
}
