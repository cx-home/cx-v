module code

import cx
import math
import strings

// stdlib_geo.v — native primitives backing the `cx-stdlib/geo` module
// (spec/std-lib/geo.md). Coordinate primitives on the WGS84 datum
// (§1.1): Haversine + Vincenty distance, bearing, bbox / polygon ops,
// WKT + GeoJSON I/O, normalization. None of this is expressible as a
// pure CX `[?def]` body (trig, iterative Vincenty, ray-casting, OGC
// validity, format parsers), so the bundle bodies (stdlib_src_geo)
// forward to the `geo-*` primitives dispatched here. See
// stdlib_dispatch.v for the registration line.
//
// ── value model (spec §2) ───────────────────────────────────────────
//   point   → [point [lat <f64>] [lon <f64>]]  — coordinates are CHILD
//             elements (not attributes) so `$p/lat` resolves via the
//             child axis and §6.2 terminal-field unwrap yields the bare
//             float scalar (the fixtures assert `37.7749`, not an
//             element render).
//   bbox    → [bbox [min-lat][max-lat][min-lon][max-lon]]  (inclusive;
//             antimeridian crossing has min-lon > max-lon).
//   polygon → [polygon [ring [point]…] [hole [point]…]…]  — first ring
//             is the outer boundary; [hole] rings are interior.
//   feature → [feature [geometry <tagged>] [properties <__cx_map__>]].
//   collection → [geometry-collection <geom>…].
//
// Errors are VALUE nodes (mk_err, eval.v): the spec §5 codes
// CXER3600..CXER3605. The conformance runner matches the bare code in
// `out-err`.

// ── error codes (spec §5) ────────────────────────────────────────────
const geo_err_vincenty    = 'cx-err:CXER3600' // E_GEO_VINCENTY_CONVERGENCE
const geo_err_coordinate  = 'cx-err:CXER3601' // E_GEO_INVALID_COORDINATE
const geo_err_polygon     = 'cx-err:CXER3602' // E_GEO_POLYGON_INVALID
const geo_err_wkt         = 'cx-err:CXER3603' // E_GEO_WKT_MALFORMED
const geo_err_geojson     = 'cx-err:CXER3604' // E_GEO_GEOJSON_MALFORMED
const geo_err_unsupported = 'cx-err:CXER3605' // E_GEO_GEOMETRY_TYPE_UNSUPPORTED

// ── earth-model constants ────────────────────────────────────────────
// Haversine uses the IUGG mean radius; pinned so NYC→LAX centres on the
// §6 canonical ~3944 km band (within the 1% fixture tolerance).
const geo_earth_radius_km = 6371.0088
// WGS84 ellipsoid parameters (Vincenty + geodesic area).
const geo_wgs84_a = 6378137.0            // semi-major axis (m)
const geo_wgs84_f = 1.0 / 298.257223563  // flattening
const geo_wgs84_b = geo_wgs84_a * (1.0 - geo_wgs84_f) // semi-minor (m)

// ── scalar / node builders ───────────────────────────────────────────

fn geo_float(f f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(f)
		data_type: cx.ScalarType.float_type
	}
}

fn geo_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn geo_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

// geo_field builds a single labeled child element [name <scalar>] so
// `$x/name` resolves to the bare scalar via §6.2 terminal-field unwrap.
fn geo_field(name string, v cx.Node) cx.Node {
	return cx.Element{
		name:  name
		items: [v]
	}
}

fn geo_point(lat f64, lon f64) cx.Node {
	return cx.Element{
		name:  'point'
		items: [geo_field('lat', geo_float(lat)), geo_field('lon', geo_float(lon))]
	}
}

fn geo_bbox(min_lat f64, max_lat f64, min_lon f64, max_lon f64) cx.Node {
	return cx.Element{
		name:  'bbox'
		items: [
			geo_field('min-lat', geo_float(min_lat)),
			geo_field('max-lat', geo_float(max_lat)),
			geo_field('min-lon', geo_float(min_lon)),
			geo_field('max-lon', geo_float(max_lon)),
		]
	}
}

// ── argument readers ─────────────────────────────────────────────────

fn geo_arg_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			string { return v.f64() }
			else {}
		}
	}
	return none
}

fn geo_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// geo_items extracts the materialized item list of any sequence-shaped
// node: a __cx_seq__ / __cx_arr__ element, a bare anonymous element, or
// an eager IteratorNode whose memo carries the items.
fn geo_items(n cx.Node) []cx.Node {
	match n {
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
				return n.items
			}
		}
		cx.IteratorNode {
			return n.memo
		}
		else {}
	}
	return []cx.Node{}
}

// geo_child_f64 reads the scalar held by a child element [name <scalar>].
fn geo_child_f64(el cx.Element, name string) ?f64 {
	for c in el.items {
		if c is cx.Element && c.name == name && c.items.len > 0 {
			return geo_arg_f64(c.items[0])
		}
	}
	return none
}

// geo_as_element narrows a Node to an Element of the given name.
fn geo_as_element(n cx.Node, name string) ?cx.Element {
	if n is cx.Element && n.name == name {
		return n
	}
	return none
}

// geo_point_coords reads (lat, lon) off a [point …] element.
fn geo_point_coords(n cx.Node) ?(f64, f64) {
	el := geo_as_element(n, 'point') or { return none }
	lat := geo_child_f64(el, 'lat') or { return none }
	lon := geo_child_f64(el, 'lon') or { return none }
	return lat, lon
}

// geo_bbox_bounds reads (min_lat, max_lat, min_lon, max_lon) off [bbox …].
fn geo_bbox_bounds(n cx.Node) ?(f64, f64, f64, f64) {
	el := geo_as_element(n, 'bbox') or { return none }
	min_lat := geo_child_f64(el, 'min-lat') or { return none }
	max_lat := geo_child_f64(el, 'max-lat') or { return none }
	min_lon := geo_child_f64(el, 'min-lon') or { return none }
	max_lon := geo_child_f64(el, 'max-lon') or { return none }
	return min_lat, max_lat, min_lon, max_lon
}

// ── angle helpers ────────────────────────────────────────────────────

fn geo_rad(deg f64) f64 {
	return deg * math.pi / 180.0
}

fn geo_deg(rad f64) f64 {
	return rad * 180.0 / math.pi
}

// ── unit tables ──────────────────────────────────────────────────────
// Length units → kilometres-per-unit (Haversine works in km internally).
fn geo_length_per_km(unit string) ?f64 {
	return match unit {
		'km' { 1.0 }
		'm' { 1000.0 }
		'mi' { 1.0 / 1.609344 }
		'nm' { 1.0 / 1.852 }
		else { none }
	}
}

// Area units → value-per-square-metre (areas computed in m²).
fn geo_area_per_m2(unit string) ?f64 {
	return match unit {
		'm2' { 1.0 }
		'km2' { 1.0 / 1_000_000.0 }
		'mi2' { 1.0 / (1609.344 * 1609.344) }
		'acres' { 1.0 / 4046.8564224 }
		'hectares' { 1.0 / 10_000.0 }
		else { none }
	}
}

// ── distance / bearing ───────────────────────────────────────────────

// geo_haversine returns the great-circle distance in kilometres.
fn geo_haversine_km(lat1 f64, lon1 f64, lat2 f64, lon2 f64) f64 {
	p1 := geo_rad(lat1)
	p2 := geo_rad(lat2)
	dphi := geo_rad(lat2 - lat1)
	dlam := geo_rad(lon2 - lon1)
	a := math.sin(dphi / 2.0) * math.sin(dphi / 2.0) +
		math.cos(p1) * math.cos(p2) * math.sin(dlam / 2.0) * math.sin(dlam / 2.0)
	c := 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
	return geo_earth_radius_km * c
}

// geo_vincenty_m returns the WGS84-ellipsoidal distance in metres, or an
// error sentinel (none) on non-convergence (near-antipodal points).
fn geo_vincenty_m(lat1 f64, lon1 f64, lat2 f64, lon2 f64) ?f64 {
	a := geo_wgs84_a
	b := geo_wgs84_b
	f := geo_wgs84_f
	l := geo_rad(lon2 - lon1)
	u1 := math.atan((1.0 - f) * math.tan(geo_rad(lat1)))
	u2 := math.atan((1.0 - f) * math.tan(geo_rad(lat2)))
	sin_u1 := math.sin(u1)
	cos_u1 := math.cos(u1)
	sin_u2 := math.sin(u2)
	cos_u2 := math.cos(u2)
	mut lambda := l
	mut iter := 0
	mut cos_sq_alpha := 0.0
	mut sin_sigma := 0.0
	mut cos_sigma := 0.0
	mut cos_2sigma_m := 0.0
	mut sigma := 0.0
	for iter < 1000 {
		sin_lambda := math.sin(lambda)
		cos_lambda := math.cos(lambda)
		sin_sigma = math.sqrt((cos_u2 * sin_lambda) * (cos_u2 * sin_lambda) +
			(cos_u1 * sin_u2 - sin_u1 * cos_u2 * cos_lambda) *
			(cos_u1 * sin_u2 - sin_u1 * cos_u2 * cos_lambda))
		if sin_sigma == 0.0 {
			return 0.0 // coincident points
		}
		cos_sigma = sin_u1 * sin_u2 + cos_u1 * cos_u2 * cos_lambda
		sigma = math.atan2(sin_sigma, cos_sigma)
		sin_alpha := cos_u1 * cos_u2 * sin_lambda / sin_sigma
		cos_sq_alpha = 1.0 - sin_alpha * sin_alpha
		if cos_sq_alpha == 0.0 {
			cos_2sigma_m = 0.0 // equatorial line
		} else {
			cos_2sigma_m = cos_sigma - 2.0 * sin_u1 * sin_u2 / cos_sq_alpha
		}
		c := f / 16.0 * cos_sq_alpha * (4.0 + f * (4.0 - 3.0 * cos_sq_alpha))
		lambda_prev := lambda
		lambda = l + (1.0 - c) * f * sin_alpha *
			(sigma + c * sin_sigma * (cos_2sigma_m + c * cos_sigma *
			(-1.0 + 2.0 * cos_2sigma_m * cos_2sigma_m)))
		if math.abs(lambda - lambda_prev) < 1e-12 {
			u_sq := cos_sq_alpha * (a * a - b * b) / (b * b)
			big_a := 1.0 + u_sq / 16384.0 *
				(4096.0 + u_sq * (-768.0 + u_sq * (320.0 - 175.0 * u_sq)))
			big_b := u_sq / 1024.0 * (256.0 + u_sq * (-128.0 + u_sq * (74.0 - 47.0 * u_sq)))
			delta_sigma := big_b * sin_sigma * (cos_2sigma_m + big_b / 4.0 *
				(cos_sigma * (-1.0 + 2.0 * cos_2sigma_m * cos_2sigma_m) -
				big_b / 6.0 * cos_2sigma_m * (-3.0 + 4.0 * sin_sigma * sin_sigma) *
				(-3.0 + 4.0 * cos_2sigma_m * cos_2sigma_m)))
			return b * big_a * (sigma - delta_sigma)
		}
		iter++
	}
	return none // failed to converge
}

// geo_bearing returns the initial bearing a→b in degrees (0 = north).
fn geo_bearing_deg(lat1 f64, lon1 f64, lat2 f64, lon2 f64) f64 {
	p1 := geo_rad(lat1)
	p2 := geo_rad(lat2)
	dlam := geo_rad(lon2 - lon1)
	y := math.sin(dlam) * math.cos(p2)
	x := math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dlam)
	theta := math.atan2(y, x)
	return math.fmod(geo_deg(theta) + 360.0, 360.0)
}

// geo_destination computes the Haversine forward endpoint.
fn geo_destination(lat f64, lon f64, bearing f64, dist_km f64) (f64, f64) {
	ang := dist_km / geo_earth_radius_km
	br := geo_rad(bearing)
	p1 := geo_rad(lat)
	l1 := geo_rad(lon)
	p2 := math.asin(math.sin(p1) * math.cos(ang) + math.cos(p1) * math.sin(ang) * math.cos(br))
	l2 := l1 + math.atan2(math.sin(br) * math.sin(ang) * math.cos(p1),
		math.cos(ang) - math.sin(p1) * math.sin(p2))
	return geo_deg(p2), geo_deg(l2)
}

// ── coordinate validity / normalization ──────────────────────────────

fn geo_is_valid_lat(lat f64) bool {
	return lat >= -90.0 && lat <= 90.0
}

fn geo_is_valid_lon(lon f64) bool {
	return lon >= -180.0 && lon <= 180.0
}

fn geo_norm_lat(lat f64) f64 {
	if lat > 90.0 {
		return 90.0
	}
	if lat < -90.0 {
		return -90.0
	}
	return lat
}

// geo_norm_lon wraps longitude into [-180, 180]. 190 → -170; 180 stays.
fn geo_norm_lon(lon f64) f64 {
	// Constant-time wrap into (-180, 180]. The prior loop subtracted 360°
	// per turn — O(|lon|/360), so a large finite longitude (e.g. 1e13) hung
	// the interpreter for tens of seconds (DoS), and ±inf looped forever.
	// NaN/inf short-circuit (modulo would yield NaN and the comparisons fail).
	if math.is_nan(lon) || math.is_inf(lon, 0) {
		return lon
	}
	mut l := math.fmod(lon, 360.0)
	if l > 180.0 {
		l -= 360.0
	}
	if l < -180.0 {
		l += 360.0
	}
	return l
}

// ── polygon helpers ──────────────────────────────────────────────────

// geo_ring_points reads the [point]s of a [ring]/[hole] element as a
// list of (lat, lon) pairs.
fn geo_ring_points(ring cx.Element) [][2]f64 {
	mut pts := [][2]f64{}
	for c in ring.items {
		if c is cx.Element && c.name == 'point' {
			lat := geo_child_f64(c, 'lat') or { continue }
			lon := geo_child_f64(c, 'lon') or { continue }
			pts << [lat, lon]!
		}
	}
	return pts
}

// geo_polygon_rings returns (outer, holes) point-lists of a [polygon …].
fn geo_polygon_rings(n cx.Node) ?([][2]f64, [][][2]f64) {
	el := geo_as_element(n, 'polygon') or { return none }
	mut outer := [][2]f64{}
	mut holes := [][][2]f64{}
	for c in el.items {
		if c is cx.Element {
			if c.name == 'ring' {
				outer = geo_ring_points(c)
			} else if c.name == 'hole' {
				holes << geo_ring_points(c)
			}
		}
	}
	return outer, holes
}

fn geo_ring_is_closed(pts [][2]f64) bool {
	if pts.len < 2 {
		return false
	}
	first := pts[0]
	last := pts[pts.len - 1]
	return first[0] == last[0] && first[1] == last[1]
}

// geo_signed_area returns the planar signed area (lon=x, lat=y); positive
// = counterclockwise. Used for winding + degeneracy + planar centroid.
fn geo_signed_area(pts [][2]f64) f64 {
	if pts.len < 3 {
		return 0.0
	}
	mut sum := 0.0
	for i in 0 .. pts.len - 1 {
		x1 := pts[i][1]
		y1 := pts[i][0]
		x2 := pts[i + 1][1]
		y2 := pts[i + 1][0]
		sum += x1 * y2 - x2 * y1
	}
	return sum / 2.0
}

// geo_point_in_ring runs the ray-casting test (lon=x, lat=y).
fn geo_point_in_ring(lat f64, lon f64, pts [][2]f64) bool {
	mut inside := false
	n := pts.len
	if n < 3 {
		return false
	}
	mut j := n - 1
	for i in 0 .. n {
		yi := pts[i][0]
		xi := pts[i][1]
		yj := pts[j][0]
		xj := pts[j][1]
		intersect := ((yi > lat) != (yj > lat)) &&
			(lon < (xj - xi) * (lat - yi) / (yj - yi) + xi)
		if intersect {
			inside = !inside
		}
		j = i
	}
	return inside
}

// ── segment-intersection (self-intersection / OGC validity) ──────────

fn geo_orient(px f64, py f64, qx f64, qy f64, rx f64, ry f64) f64 {
	return (qx - px) * (ry - py) - (qy - py) * (rx - px)
}

fn geo_on_seg(px f64, py f64, qx f64, qy f64, rx f64, ry f64) bool {
	return math.min(px, rx) <= qx && qx <= math.max(px, rx) && math.min(py, ry) <= qy
		&& qy <= math.max(py, ry)
}

// geo_segs_cross reports whether segment (a,b) crosses (c,d). Shared
// endpoints (adjacent edges) are NOT treated as crossings.
fn geo_segs_cross(ax f64, ay f64, bx f64, by f64, cx_ f64, cy f64, dx f64, dy f64) bool {
	d1 := geo_orient(cx_, cy, dx, dy, ax, ay)
	d2 := geo_orient(cx_, cy, dx, dy, bx, by)
	d3 := geo_orient(ax, ay, bx, by, cx_, cy)
	d4 := geo_orient(ax, ay, bx, by, dx, dy)
	if ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0))
		&& ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0)) {
		return true
	}
	// Collinear-overlap cases are treated as non-crossing here; proper
	// touching is handled by the shared-endpoint allowance.
	return false
}

// geo_ring_self_intersects reports whether any two non-adjacent edges of
// the closed ring cross (OGC validity; naive O(n²) per §3.4).
fn geo_ring_self_intersects(pts [][2]f64) bool {
	n := pts.len
	if n < 4 {
		return false
	}
	// edges: i .. i+1, for i in 0 .. n-1 (ring is explicitly closed).
	m := n - 1 // number of edges
	for i in 0 .. m {
		ax := pts[i][1]
		ay := pts[i][0]
		bx := pts[i + 1][1]
		by := pts[i + 1][0]
		for k in i + 1 .. m {
			// skip adjacent edges (shared endpoint) and the wrap-around
			// pair (last edge adjacent to first).
			if k == i + 1 {
				continue
			}
			if i == 0 && k == m - 1 {
				continue
			}
			cx0 := pts[k][1]
			cy0 := pts[k][0]
			dx0 := pts[k + 1][1]
			dy0 := pts[k + 1][0]
			if geo_segs_cross(ax, ay, bx, by, cx0, cy0, dx0, dy0) {
				return true
			}
		}
	}
	return false
}

// geo_polygon_valid runs the full OGC SFA validity check (§3.4).
fn geo_polygon_valid(outer [][2]f64, holes [][][2]f64) bool {
	// closed outer ring with ≥ 3 distinct vertices
	if outer.len < 4 || !geo_ring_is_closed(outer) {
		return false
	}
	area := geo_signed_area(outer)
	// non-degenerate (zero-area ring is invalid)
	if math.abs(area) < 1e-12 {
		return false
	}
	// outer must be counterclockwise (positive signed area; OGC RHR)
	if area <= 0.0 {
		return false
	}
	if geo_ring_self_intersects(outer) {
		return false
	}
	for hole in holes {
		if hole.len < 4 || !geo_ring_is_closed(hole) {
			return false
		}
		harea := geo_signed_area(hole)
		if math.abs(harea) < 1e-12 {
			return false
		}
		// holes must be clockwise (negative signed area)
		if harea >= 0.0 {
			return false
		}
		if geo_ring_self_intersects(hole) {
			return false
		}
		// hole must lie inside the outer ring (test a representative vertex)
		if !geo_point_in_ring(hole[0][0], hole[0][1], outer) {
			return false
		}
	}
	return true
}

// geo_ring_geodesic_area_m2 returns the spherical-excess geodesic area of
// a closed ring on the WGS84 sphere-equivalent radius, in m² (absolute).
fn geo_ring_geodesic_area_m2(pts [][2]f64) f64 {
	n := pts.len
	if n < 4 {
		return 0.0
	}
	// authalic radius approximation for area
	r := (2.0 * geo_wgs84_a + geo_wgs84_b) / 3.0
	mut total := 0.0
	for i in 0 .. n - 1 {
		lon1 := geo_rad(pts[i][1])
		lat1 := geo_rad(pts[i][0])
		lon2 := geo_rad(pts[i + 1][1])
		lat2 := geo_rad(pts[i + 1][0])
		total += (lon2 - lon1) * (2.0 + math.sin(lat1) + math.sin(lat2))
	}
	area := total * r * r / 2.0
	return math.abs(area)
}

// ── WKT ──────────────────────────────────────────────────────────────

fn geo_fmt_f64(f f64) string {
	return f64_str_trim(f)
}

// f64_str_trim renders a float in WKT/GeoJSON-friendly form: integers
// without a trailing `.0`, others via the default float formatting.
fn f64_str_trim(f f64) string {
	if f == math.floor(f) && math.abs(f) < 1e15 {
		return i64(f).str()
	}
	return f.str()
}

fn geo_parse_wkt(s string) cx.Node {
	t := s.trim_space()
	up := t.to_upper()
	if up.starts_with('POINT') {
		return geo_parse_wkt_point(t)
	}
	if up.starts_with('POLYGON') {
		return geo_parse_wkt_polygon(t)
	}
	if up.starts_with('LINESTRING') {
		return geo_parse_wkt_linestring(t)
	}
	return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: unrecognized WKT: ${s}')
}

// geo_extract_parens returns the substring between the first '(' and the
// matching final ')'.
fn geo_extract_parens(s string) ?string {
	open := s.index('(') or { return none }
	close := s.last_index(')') or { return none }
	if close <= open {
		return none
	}
	return s[open + 1..close]
}

// geo_parse_coord_pair parses "lon lat" → (lat, lon).
fn geo_parse_coord_pair(s string) ?(f64, f64) {
	parts := s.trim_space().split(' ').filter(it.trim_space() != '')
	if parts.len < 2 {
		return none
	}
	lon := parts[0].trim_space().f64()
	lat := parts[1].trim_space().f64()
	// reject non-numeric tokens (V's f64() yields 0 for garbage)
	if !geo_is_numeric(parts[0].trim_space()) || !geo_is_numeric(parts[1].trim_space()) {
		return none
	}
	return lat, lon
}

fn geo_is_numeric(s string) bool {
	if s.len == 0 {
		return false
	}
	mut seen_digit := false
	for i, c in s {
		if c >= `0` && c <= `9` {
			seen_digit = true
		} else if c == `-` || c == `+` {
			if i != 0 {
				return false
			}
		} else if c == `.` || c == `e` || c == `E` {
			// allowed
		} else {
			return false
		}
	}
	return seen_digit
}

fn geo_parse_wkt_point(s string) cx.Node {
	inner := geo_extract_parens(s) or {
		return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
	}
	lat, lon := geo_parse_coord_pair(inner) or {
		return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
	}
	return geo_point(lat, lon)
}

fn geo_parse_wkt_linestring(s string) cx.Node {
	inner := geo_extract_parens(s) or {
		return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
	}
	mut items := []cx.Node{}
	for pair in inner.split(',') {
		lat, lon := geo_parse_coord_pair(pair) or {
			return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
		}
		items << geo_point(lat, lon)
	}
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn geo_parse_wkt_polygon(s string) cx.Node {
	inner := geo_extract_parens(s) or {
		return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
	}
	// inner is "(ring1)(, )(ring2)…" — split on ")," boundaries.
	mut rings := []string{}
	mut depth := 0
	mut cur := strings.new_builder(32)
	for c in inner {
		if c == `(` {
			depth++
			if depth == 1 {
				continue
			}
		}
		if c == `)` {
			depth--
			if depth == 0 {
				rings << cur.str()
				cur = strings.new_builder(32)
				continue
			}
		}
		if depth >= 1 {
			cur.write_u8(c)
		}
	}
	if rings.len == 0 {
		return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
	}
	mut ring_elems := []cx.Node{}
	for ri, ring_str in rings {
		mut pts := []cx.Node{}
		for pair in ring_str.split(',') {
			if pair.trim_space() == '' {
				continue
			}
			lat, lon := geo_parse_coord_pair(pair) or {
				return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: ${s}')
			}
			pts << geo_point(lat, lon)
		}
		ring_elems << cx.Element{
			name:  if ri == 0 { 'ring' } else { 'hole' }
			items: pts
		}
	}
	return cx.Element{
		name:  'polygon'
		items: ring_elems
	}
}

// geo_format_wkt renders a geometry element to canonical OGC WKT.
fn geo_format_wkt(n cx.Node) cx.Node {
	if lat, lon := geo_point_coords(n) {
		return geo_str('POINT(${geo_fmt_f64(lon)} ${geo_fmt_f64(lat)})')
	}
	if outer, holes := geo_polygon_rings(n) {
		mut ring_strs := []string{}
		ring_strs << geo_wkt_ring(outer)
		for h in holes {
			ring_strs << geo_wkt_ring(h)
		}
		return geo_str('POLYGON(${ring_strs.join(', ')})')
	}
	if n is cx.Element && (n as cx.Element).name == '__cx_seq__' {
		// LINESTRING
		el := n as cx.Element
		mut coords := []string{}
		for it in el.items {
			if lat, lon := geo_point_coords(it) {
				coords << '${geo_fmt_f64(lon)} ${geo_fmt_f64(lat)}'
			}
		}
		return geo_str('LINESTRING(${coords.join(', ')})')
	}
	return mk_err(geo_err_wkt, 'E_GEO_WKT_MALFORMED: not a formattable geometry')
}

fn geo_wkt_ring(pts [][2]f64) string {
	mut coords := []string{}
	for p in pts {
		coords << '${geo_fmt_f64(p[1])} ${geo_fmt_f64(p[0])}'
	}
	return '(${coords.join(', ')})'
}

// ── GeoJSON ──────────────────────────────────────────────────────────

// geo_parse_geojson parses a GeoJSON string (via the native JSON parser)
// into a tagged geometry / feature element.
fn geo_parse_geojson(s string) cx.Node {
	parsed := json_do_parse(s, map[string]cx.Node{})
	if parsed is cx.ScalarNode {
		// malformed JSON surfaces as a json err scalar — remap to geo code
		// (json_do_parse returns an err element, not a scalar, on failure;
		// a bare scalar here means a non-object top-level which is invalid).
		return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: ${s}')
	}
	if geo_is_err_node(parsed) {
		return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: ${s}')
	}
	mp := parsed
	if mp is cx.Element && mp.name == '__cx_map__' {
		return geo_geojson_obj_to_geom(mp)
	}
	return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: ${s}')
}

// geo_is_err_node reports whether a node is an `[err …]` value envelope.
fn geo_is_err_node(n cx.Node) bool {
	if n is cx.Element {
		return n.name == 'err'
	}
	return false
}

// geo_map_get returns the value node for `key` in a __cx_map__ element.
fn geo_map_get(mp cx.Element, key string) ?cx.Node {
	for e in mp.items {
		if e is cx.Element && e.name == key && e.items.len > 0 {
			return e.items[0]
		}
	}
	return none
}

fn geo_map_str(mp cx.Element, key string) ?string {
	v := geo_map_get(mp, key) or { return none }
	return geo_arg_str(v)
}

// geo_geojson_coords reads a [lon, lat] JSON array → (lat, lon).
fn geo_geojson_coords(n cx.Node) ?(f64, f64) {
	items := geo_items(n)
	if items.len < 2 {
		return none
	}
	lon := geo_arg_f64(items[0]) or { return none }
	lat := geo_arg_f64(items[1]) or { return none }
	return lat, lon
}

fn geo_geojson_obj_to_geom(mp cx.Element) cx.Node {
	typ := geo_map_str(mp, 'type') or {
		return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing type')
	}
	match typ {
		'Point' {
			coords := geo_map_get(mp, 'coordinates') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing coordinates')
			}
			lat, lon := geo_geojson_coords(coords) or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: bad coordinates')
			}
			return geo_point(lat, lon)
		}
		'MultiPoint' {
			coords := geo_map_get(mp, 'coordinates') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing coordinates')
			}
			mut pts := []cx.Node{}
			for c in geo_items(coords) {
				lat, lon := geo_geojson_coords(c) or {
					return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: bad coordinates')
				}
				pts << geo_point(lat, lon)
			}
			return cx.Element{
				name:  'geometry-collection'
				items: pts
			}
		}
		'LineString' {
			coords := geo_map_get(mp, 'coordinates') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing coordinates')
			}
			mut pts := []cx.Node{}
			for c in geo_items(coords) {
				lat, lon := geo_geojson_coords(c) or {
					return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: bad coordinates')
				}
				pts << geo_point(lat, lon)
			}
			return cx.Element{
				name:  '__cx_seq__'
				items: pts
			}
		}
		'Polygon' {
			coords := geo_map_get(mp, 'coordinates') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing coordinates')
			}
			return geo_geojson_rings_to_polygon(coords)
		}
		'GeometryCollection' {
			geoms := geo_map_get(mp, 'geometries') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing geometries')
			}
			mut items := []cx.Node{}
			for g in geo_items(geoms) {
				if g is cx.Element && g.name == '__cx_map__' {
					sub := geo_geojson_obj_to_geom(g)
					if geo_is_err_node(sub) {
						return sub
					}
					items << sub
				}
			}
			return cx.Element{
				name:  'geometry-collection'
				items: items
			}
		}
		'Feature' {
			geom_node := geo_map_get(mp, 'geometry') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing geometry')
			}
			mut geom := cx.Node(cx.Element{
				name: ''
			})
			if geom_node is cx.Element && geom_node.name == '__cx_map__' {
				geom = geo_geojson_obj_to_geom(geom_node)
				if geo_is_err_node(geom) {
					return geom
				}
			}
			props := geo_map_get(mp, 'properties') or { cx.Node(cx.Element{
				name: '__cx_map__'
			}) }
			return cx.Element{
				name:  'feature'
				items: [
					cx.Node(cx.Element{
						name:  'geometry'
						items: [geom]
					}),
					cx.Node(cx.Element{
						name:  'properties'
						items: [props]
					}),
				]
			}
		}
		'FeatureCollection' {
			feats := geo_map_get(mp, 'features') or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: missing features')
			}
			mut items := []cx.Node{}
			for fnode in geo_items(feats) {
				if fnode is cx.Element && fnode.name == '__cx_map__' {
					sub := geo_geojson_obj_to_geom(fnode)
					if geo_is_err_node(sub) {
						return sub
					}
					items << sub
				}
			}
			return cx.Element{
				name:  'geometry-collection'
				items: items
			}
		}
		else {
			return mk_err(geo_err_unsupported, 'E_GEO_GEOMETRY_TYPE_UNSUPPORTED: ${typ}')
		}
	}
}

fn geo_geojson_rings_to_polygon(coords cx.Node) cx.Node {
	rings := geo_items(coords)
	if rings.len == 0 {
		return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: empty polygon')
	}
	mut ring_elems := []cx.Node{}
	for ri, ring in rings {
		mut pts := []cx.Node{}
		for c in geo_items(ring) {
			lat, lon := geo_geojson_coords(c) or {
				return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: bad coordinates')
			}
			pts << geo_point(lat, lon)
		}
		ring_elems << cx.Element{
			name:  if ri == 0 { 'ring' } else { 'hole' }
			items: pts
		}
	}
	return cx.Element{
		name:  'polygon'
		items: ring_elems
	}
}

// geo_format_geojson renders a geometry element to a GeoJSON string.
fn geo_format_geojson(n cx.Node) cx.Node {
	if lat, lon := geo_point_coords(n) {
		return geo_str('{"type":"Point","coordinates":[${geo_fmt_f64(lon)},${geo_fmt_f64(lat)}]}')
	}
	if outer, holes := geo_polygon_rings(n) {
		mut rings := []string{}
		rings << geo_geojson_ring(outer)
		for h in holes {
			rings << geo_geojson_ring(h)
		}
		return geo_str('{"type":"Polygon","coordinates":[${rings.join(',')}]}')
	}
	if n is cx.Element {
		el := n as cx.Element
		if el.name == 'feature' {
			return geo_format_geojson_feature(el)
		}
		if el.name == 'geometry-collection' {
			mut geoms := []string{}
			for it in el.items {
				sub := geo_format_geojson(it)
				if s := geo_arg_str(sub) {
					geoms << s
				}
			}
			return geo_str('{"type":"GeometryCollection","geometries":[${geoms.join(',')}]}')
		}
		if el.name == '__cx_seq__' {
			mut coords := []string{}
			for it in el.items {
				if lat, lon := geo_point_coords(it) {
					coords << '[${geo_fmt_f64(lon)},${geo_fmt_f64(lat)}]'
				}
			}
			return geo_str('{"type":"LineString","coordinates":[${coords.join(',')}]}')
		}
	}
	return mk_err(geo_err_geojson, 'E_GEO_GEOJSON_MALFORMED: not a formattable geometry')
}

fn geo_format_geojson_feature(el cx.Element) cx.Node {
	mut geom_str := '{}'
	mut props_str := '{}'
	for c in el.items {
		if c is cx.Element {
			if c.name == 'geometry' && c.items.len > 0 {
				sub := geo_format_geojson(c.items[0])
				if s := geo_arg_str(sub) {
					geom_str = s
				}
			} else if c.name == 'properties' && c.items.len > 0 {
				emitted := json_emit_with(c.items[0], 0, false, false, 'null')
				if s := geo_arg_str(emitted) {
					props_str = s
				}
			}
		}
	}
	return geo_str('{"type":"Feature","geometry":${geom_str},"properties":${props_str}}')
}

fn geo_geojson_ring(pts [][2]f64) string {
	mut coords := []string{}
	for p in pts {
		coords << '[${geo_fmt_f64(p[1])},${geo_fmt_f64(p[0])}]'
	}
	return '[${coords.join(',')}]'
}

// ── dispatch ─────────────────────────────────────────────────────────

fn geo_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §3.1 construction ────────────────────────────────────────
		'geo-point' {
			lat := geo_arg_f64(args[0]) or { return none }
			lon := geo_arg_f64(args[1]) or { return none }
			// Coordinate canonicalization (geo.md §2.1): longitude is CYCLIC
			// (±180 is the same meridian), so it is wrapped into [-180, 180] —
			// a constructed point is ALWAYS longitude-canonical and lon=190
			// becomes -170 losslessly. Latitude is NON-cyclic: out of
			// [-90, 90] is a hard CXER3601 error, never silently clamped
			// (clamping is lossy and masks bugs; the explicit normalize-lat
			// helper is the opt-in escape hatch for raw numeric pipelines).
			if !geo_is_valid_lat(lat) {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: lat=${lat} out of [-90, 90]')
			}
			return geo_point(lat, geo_norm_lon(lon))
		}
		'geo-bbox' {
			// Corner form (§2.2): arg0 is the SW (min) corner, arg1 the NE
			// (max) corner — assigned directly so an antimeridian-crossing
			// bbox (min-lon > max-lon) is preserved, not collapsed by a
			// min/max recompute. `bbox-of` is the minimum-bbox reducer.
			pts := geo_items(args[0])
			if pts.len >= 2 {
				lat0, lon0 := geo_point_coords(pts[0]) or { return none }
				lat1, lon1 := geo_point_coords(pts[1]) or { return none }
				return geo_bbox(lat0, lat1, lon0, lon1)
			}
			return geo_bbox_of(pts)
		}
		'geo-polygon' {
			// `polygon(outer)` auto-closes the ring if open (§3.1).
			pts := geo_items(args[0])
			return geo_make_polygon(pts, [][]cx.Node{}, true)
		}
		'geo-polygon-with-holes' {
			// `polygon-with-holes` preserves rings verbatim (no auto-close):
			// closure is the caller's responsibility, and polygon-is-closed
			// (geo-039) must observe an open ring as not-closed.
			outer := geo_items(args[0])
			mut holes := [][]cx.Node{}
			for h in geo_items(args[1]) {
				holes << geo_items(h)
			}
			return geo_make_polygon(outer, holes, false)
		}

		// ── §3.2 distance and bearing ────────────────────────────────
		'geo-distance' {
			lat1, lon1 := geo_point_coords(args[0]) or { return none }
			lat2, lon2 := geo_point_coords(args[1]) or { return none }
			unit := geo_arg_str(args[2]) or { return none }
			per_km := geo_length_per_km(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown unit ${unit}')
			}
			km := geo_haversine_km(lat1, lon1, lat2, lon2)
			return geo_float(km * per_km)
		}
		'geo-distance-vincenty' {
			lat1, lon1 := geo_point_coords(args[0]) or { return none }
			lat2, lon2 := geo_point_coords(args[1]) or { return none }
			unit := geo_arg_str(args[2]) or { return none }
			per_km := geo_length_per_km(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown unit ${unit}')
			}
			m := geo_vincenty_m(lat1, lon1, lat2, lon2) or {
				return mk_err(geo_err_vincenty, 'E_GEO_VINCENTY_CONVERGENCE: near-antipodal points')
			}
			return geo_float((m / 1000.0) * per_km)
		}
		'geo-bearing' {
			lat1, lon1 := geo_point_coords(args[0]) or { return none }
			lat2, lon2 := geo_point_coords(args[1]) or { return none }
			return geo_float(geo_bearing_deg(lat1, lon1, lat2, lon2))
		}
		'geo-destination' {
			lat, lon := geo_point_coords(args[0]) or { return none }
			bearing := geo_arg_f64(args[1]) or { return none }
			dist := geo_arg_f64(args[2]) or { return none }
			unit := geo_arg_str(args[3]) or { return none }
			per_km := geo_length_per_km(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown unit ${unit}')
			}
			dist_km := dist / per_km
			dlat, dlon := geo_destination(lat, lon, bearing, dist_km)
			return geo_point(dlat, geo_norm_lon(dlon))
		}

		// ── §3.3 bounding-box operations ─────────────────────────────
		'geo-bbox-of' {
			return geo_bbox_of(geo_items(args[0]))
		}
		'geo-bbox-of-polygon' {
			outer, holes := geo_polygon_rings(args[0]) or { return none }
			mut all := outer.clone()
			for h in holes {
				all << h
			}
			return geo_bbox_of_pairs(all)
		}
		'geo-within-bbox' {
			lat, lon := geo_point_coords(args[0]) or { return none }
			min_lat, max_lat, min_lon, max_lon := geo_bbox_bounds(args[1]) or { return none }
			lat_in := lat >= min_lat && lat <= max_lat
			mut lon_in := false
			if min_lon <= max_lon {
				lon_in = lon >= min_lon && lon <= max_lon
			} else {
				// antimeridian-crossing band: [min_lon, 180] ∪ [-180, max_lon]
				lon_in = lon >= min_lon || lon <= max_lon
			}
			return geo_bool(lat_in && lon_in)
		}
		'geo-bbox-intersects' {
			a_min_lat, a_max_lat, a_min_lon, a_max_lon := geo_bbox_bounds(args[0]) or {
				return none
			}
			b_min_lat, b_max_lat, b_min_lon, b_max_lon := geo_bbox_bounds(args[1]) or {
				return none
			}
			lat_overlap := a_min_lat <= b_max_lat && b_min_lat <= a_max_lat
			lon_overlap := geo_lon_ranges_overlap(a_min_lon, a_max_lon, b_min_lon, b_max_lon)
			return geo_bool(lat_overlap && lon_overlap)
		}
		'geo-bbox-area' {
			min_lat, max_lat, min_lon, max_lon := geo_bbox_bounds(args[0]) or { return none }
			unit := geo_arg_str(args[1]) or { return none }
			per_m2 := geo_area_per_m2(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown area unit ${unit}')
			}
			ring := [
				[min_lat, min_lon]!,
				[min_lat, max_lon]!,
				[max_lat, max_lon]!,
				[max_lat, min_lon]!,
				[min_lat, min_lon]!,
			]
			m2 := geo_ring_geodesic_area_m2(ring)
			return geo_float(m2 * per_m2)
		}
		'geo-bbox-expand' {
			min_lat, max_lat, min_lon, max_lon := geo_bbox_bounds(args[0]) or { return none }
			by_m := geo_arg_f64(args[1]) or { return none }
			if by_m == 0.0 {
				return geo_bbox(min_lat, max_lat, min_lon, max_lon)
			}
			// degrees per metre (lat); lon scaled by cos(mid-lat)
			dlat := by_m / 111_320.0
			mid_lat := (min_lat + max_lat) / 2.0
			cos_mid := math.cos(geo_rad(mid_lat))
			dlon := if cos_mid == 0.0 { 0.0 } else { by_m / (111_320.0 * cos_mid) }
			return geo_bbox(geo_norm_lat(min_lat - dlat), geo_norm_lat(max_lat + dlat),
				min_lon - dlon, max_lon + dlon)
		}
		'geo-bbox-center' {
			min_lat, max_lat, min_lon, max_lon := geo_bbox_bounds(args[0]) or { return none }
			clat := (min_lat + max_lat) / 2.0
			mut clon := (min_lon + max_lon) / 2.0
			if min_lon > max_lon {
				// antimeridian-crossing midpoint
				clon = geo_norm_lon((min_lon + max_lon + 360.0) / 2.0)
			}
			return geo_point(clat, clon)
		}

		// ── §3.4 polygon operations ──────────────────────────────────
		'geo-polygon-area' {
			outer, holes := geo_polygon_rings(args[0]) or { return none }
			unit := geo_arg_str(args[1]) or { return none }
			per_m2 := geo_area_per_m2(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown area unit ${unit}')
			}
			if !geo_polygon_valid(outer, holes) {
				return mk_err(geo_err_polygon, 'E_GEO_POLYGON_INVALID: polygon fails OGC validity')
			}
			mut m2 := geo_ring_geodesic_area_m2(outer)
			for h in holes {
				m2 -= geo_ring_geodesic_area_m2(h)
			}
			return geo_float(m2 * per_m2)
		}
		'geo-polygon-perimeter' {
			outer, _ := geo_polygon_rings(args[0]) or { return none }
			unit := geo_arg_str(args[1]) or { return none }
			per_km := geo_length_per_km(unit) or {
				return mk_err(geo_err_coordinate, 'E_GEO_INVALID_COORDINATE: unknown unit ${unit}')
			}
			mut km := 0.0
			for i in 0 .. outer.len - 1 {
				km += geo_haversine_km(outer[i][0], outer[i][1], outer[i + 1][0],
					outer[i + 1][1])
			}
			return geo_float(km * per_km)
		}
		'geo-polygon-centroid' {
			outer, _ := geo_polygon_rings(args[0]) or { return none }
			clat, clon := geo_ring_centroid(outer)
			return geo_point(clat, clon)
		}
		'geo-point-in-polygon' {
			lat, lon := geo_point_coords(args[0]) or { return none }
			outer, holes := geo_polygon_rings(args[1]) or { return none }
			mut inside := geo_point_in_ring(lat, lon, outer)
			if inside {
				for h in holes {
					if geo_point_in_ring(lat, lon, h) {
						inside = false
						break
					}
				}
			}
			return geo_bool(inside)
		}
		'geo-polygon-is-valid' {
			outer, holes := geo_polygon_rings(args[0]) or { return none }
			return geo_bool(geo_polygon_valid(outer, holes))
		}
		'geo-polygon-is-closed' {
			outer, holes := geo_polygon_rings(args[0]) or { return none }
			mut closed := geo_ring_is_closed(outer)
			for h in holes {
				if !geo_ring_is_closed(h) {
					closed = false
				}
			}
			return geo_bool(closed)
		}

		// ── §3.5 normalization ───────────────────────────────────────
		'geo-normalize-lat' {
			lat := geo_arg_f64(args[0]) or { return none }
			return geo_float(geo_norm_lat(lat))
		}
		'geo-normalize-lon' {
			lon := geo_arg_f64(args[0]) or { return none }
			return geo_float(geo_norm_lon(lon))
		}
		'geo-normalize-point' {
			lat, lon := geo_point_coords(args[0]) or { return none }
			return geo_point(geo_norm_lat(lat), geo_norm_lon(lon))
		}
		'geo-normalize-bbox' {
			min_lat, max_lat, min_lon, max_lon := geo_bbox_bounds(args[0]) or { return none }
			return geo_bbox(geo_norm_lat(min_lat), geo_norm_lat(max_lat), geo_norm_lon(min_lon),
				geo_norm_lon(max_lon))
		}
		'geo-is-valid-lat' {
			lat := geo_arg_f64(args[0]) or { return none }
			return geo_bool(geo_is_valid_lat(lat))
		}
		'geo-is-valid-lon' {
			lon := geo_arg_f64(args[0]) or { return none }
			return geo_bool(geo_is_valid_lon(lon))
		}

		// ── §3.6 WKT ─────────────────────────────────────────────────
		'geo-parse-wkt' {
			s := geo_arg_str(args[0]) or { return none }
			return geo_parse_wkt(s)
		}
		'geo-format-wkt' {
			return geo_format_wkt(args[0])
		}

		// ── §3.7 GeoJSON ─────────────────────────────────────────────
		'geo-parse-geojson' {
			s := geo_arg_str(args[0]) or { return none }
			return geo_parse_geojson(s)
		}
		'geo-format-geojson' {
			return geo_format_geojson(args[0])
		}

		else {
			return none
		}
	}
}

// ── shared constructors / reducers ───────────────────────────────────

// geo_make_polygon builds a [polygon] from outer + hole point lists.
// When `auto_close` is set each open ring is closed (the `polygon`
// constructor); `polygon-with-holes` passes false to preserve rings.
fn geo_make_polygon(outer []cx.Node, holes [][]cx.Node, auto_close bool) cx.Node {
	mut items := []cx.Node{}
	items << cx.Element{
		name:  'ring'
		items: if auto_close { geo_close_points(outer) } else { outer.clone() }
	}
	for h in holes {
		items << cx.Element{
			name:  'hole'
			items: if auto_close { geo_close_points(h) } else { h.clone() }
		}
	}
	return cx.Element{
		name:  'polygon'
		items: items
	}
}

// geo_close_points appends the first point to close the ring when the
// last point differs from the first (spec §3.1 auto-close).
fn geo_close_points(pts []cx.Node) []cx.Node {
	if pts.len < 2 {
		return pts.clone()
	}
	mut out := pts.clone()
	flat, flon := geo_point_coords(pts[0]) or { return out }
	llat, llon := geo_point_coords(pts[pts.len - 1]) or { return out }
	if flat != llat || flon != llon {
		out << geo_point(flat, flon)
	}
	return out
}

// geo_bbox_of computes the minimum bbox over [point] nodes.
fn geo_bbox_of(pts []cx.Node) cx.Node {
	mut pairs := [][2]f64{}
	for p in pts {
		lat, lon := geo_point_coords(p) or { continue }
		pairs << [lat, lon]!
	}
	return geo_bbox_of_pairs(pairs)
}

fn geo_bbox_of_pairs(pairs [][2]f64) cx.Node {
	if pairs.len == 0 {
		return geo_bbox(0.0, 0.0, 0.0, 0.0)
	}
	mut min_lat := pairs[0][0]
	mut max_lat := pairs[0][0]
	mut min_lon := pairs[0][1]
	mut max_lon := pairs[0][1]
	for p in pairs {
		if p[0] < min_lat {
			min_lat = p[0]
		}
		if p[0] > max_lat {
			max_lat = p[0]
		}
		if p[1] < min_lon {
			min_lon = p[1]
		}
		if p[1] > max_lon {
			max_lon = p[1]
		}
	}
	return geo_bbox(min_lat, max_lat, min_lon, max_lon)
}

// geo_lon_ranges_overlap handles antimeridian-crossing ranges (min>max).
fn geo_lon_ranges_overlap(a_min f64, a_max f64, b_min f64, b_max f64) bool {
	a_wrap := a_min > a_max
	b_wrap := b_min > b_max
	if !a_wrap && !b_wrap {
		return a_min <= b_max && b_min <= a_max
	}
	if a_wrap && b_wrap {
		return true // both span the antimeridian → always overlap
	}
	// one wraps: split the wrapping range into two and test each.
	if a_wrap {
		return geo_lon_ranges_overlap(a_min, 180.0, b_min, b_max)
			|| geo_lon_ranges_overlap(-180.0, a_max, b_min, b_max)
	}
	return geo_lon_ranges_overlap(a_min, a_max, b_min, 180.0)
		|| geo_lon_ranges_overlap(a_min, a_max, -180.0, b_max)
}

// geo_ring_centroid returns the planar polygon centroid (lat, lon). For a
// degenerate (zero-area) ring it falls back to the vertex average.
fn geo_ring_centroid(pts [][2]f64) (f64, f64) {
	area := geo_signed_area(pts)
	if math.abs(area) < 1e-12 {
		// vertex average (skip the closing duplicate)
		mut slat := 0.0
		mut slon := 0.0
		n := if pts.len > 1 && geo_ring_is_closed(pts) { pts.len - 1 } else { pts.len }
		if n == 0 {
			return 0.0, 0.0
		}
		for i in 0 .. n {
			slat += pts[i][0]
			slon += pts[i][1]
		}
		return slat / f64(n), slon / f64(n)
	}
	mut cx_lon := 0.0
	mut cy_lat := 0.0
	for i in 0 .. pts.len - 1 {
		x0 := pts[i][1]
		y0 := pts[i][0]
		x1 := pts[i + 1][1]
		y1 := pts[i + 1][0]
		cross := x0 * y1 - x1 * y0
		cx_lon += (x0 + x1) * cross
		cy_lat += (y0 + y1) * cross
	}
	cx_lon /= (6.0 * area)
	cy_lat /= (6.0 * area)
	return cy_lat, cx_lon
}
