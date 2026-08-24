module main

// The scaffold bodies for `cx xap init`. Kept beside the command rather
// than read from disk so a scaffold never depends on the toolchain's own
// source tree being present.
//
// The shape mirrors the in-family reference application (reference/shop/):
// two INDEPENDENT base features, one COMPOSITE that joins them over a
// shared key, then the wiring and surface layers. It composes as generated.

fn xap_init_files(name string) map[string]string {
	return {
		'thing.feature.cxd':          xap_init_base_a(name)
		'owner.feature.cxd':          xap_init_base_b(name)
		'thing-of-owner.feature.cxd': xap_init_composite(name)
		'${name}.xap.cxd':            xap_init_xap(name)
		'${name}.surface.cxd':        xap_init_surface(name)
		'compose.cx':                 xap_init_compose(name)
		'README.md':                  xap_init_readme(name)
	}
}

// ── the pane table (RULED: ATC-2) ────────────────────────────────────────
//
// The ONE source both the surface's `[shows …]` strings and the client's
// generic table views derive from. #846's design intent — "generic table
// views derived from the feature's `shows` declarations" — is kept honest
// by construction: the scaffolder derives both sides from this table, so
// the surface and the client cannot drift apart.

struct XapInitPane {
	panel  string   // the [panel] name in the surface
	comp   string   // component (= feature) name; also the shell mount name
	noun   string   // the noun whose records the pane shows
	bind   string   // the component's state route
	region string   // surface layout region
	mode   string   // surface layout mode
	fields []string // the SHOWN fields, in column order
	verb   string   // the pane's act verb ('' = view-only pane)
	label  string   // the control's label
	slots  []string // the act verb's intent slots
}

fn xap_init_panes() []XapInitPane {
	return [
		XapInitPane{
			panel:  'things'
			comp:   'thing'
			noun:   'thing'
			bind:   '/thing'
			region: 'left'
			mode:   'separate'
			fields: ['id', 'label', 'owner']
			verb:   'create'
			label:  'Create thing'
			slots:  ['id', 'owner', 'created-at', 'label']
		},
		XapInitPane{
			panel:  'owners'
			comp:   'owner'
			noun:   'owner'
			bind:   '/owner'
			region: 'right'
			mode:   'separate'
			fields: ['id', 'name']
			verb:   'register'
			label:  'Register owner'
			slots:  ['id', 'name', 'registered-at']
		},
		XapInitPane{
			panel:  'owned'
			comp:   'thing-of-owner'
			noun:   'owned-thing'
			bind:   '/owned-thing'
			region: 'main'
			mode:   'stacked'
			fields: ['thing-id', 'owner-name', 'label']
		},
	]
}

// xap_init_shows renders one pane's `[shows …]` string: every column, as
// `noun.field`, in column order.
fn xap_init_shows(p XapInitPane) string {
	mut parts := []string{}
	for f in p.fields {
		parts << '${p.noun}.${f}'
	}
	return parts.join(' ')
}

fn xap_init_base_a(name string) string {
	return "[; A BASE feature. It knows nothing about any other feature — that
   independence is the point, and the compose gate enforces it (see the
   note in thing-of-owner.feature.cxd).

   It registers the `owner-id` KEY, which the other base registers too,
   with the same type. That agreement is what W2 checks and what makes the
   composite's join legal. ]
[feature name=thing version=\"1\"
 [summary 'The things this XAP is about. Rename it to your own noun.']

 [frames [use frame=time via=created-at]]
 [keys   [key name=owner-id via=owner]]

 [nouns
  [noun name=thing
   [field name=id type=text]
   [field name=owner type=text doc='the shared key — same name and type in owner.feature.cxd']
   [field name=created-at type=instant doc='the time-frame coordinate']
   [field name=label type=text]]]

 [verbs
  [verb name=create effect=act scope=shared consequence=reversible
   [intent [do :create]]
   [writes thing]]
  [verb name=list effect=observe
   [intent [do :list]]
   [reads thing]]]

 [rules
  [rule name=label-required kind=validity
   [statement 'A thing MUST carry a label.']]]

 [governance [grant verb=create to=operator]]

 [requirements
  [requirement kind=functional as=operator traces=create
   [want 'to create a thing'] [so 'it exists in the record']
   [acceptance 'a created thing appears under the /thing state route']]]]
"
}

fn xap_init_base_b(name string) string {
	return "[; The SECOND base feature. It registers onto the SAME `owner-id` key
   as thing.feature.cxd, with the same `text` type — W2's agreement.

   Note that both bases here define a bare `list` verb. That is legal:
   W1 requires FEATURE names to be distinct, and qualified names
   (`thing/list`, `owner/list`) keep the two apart. The consequence is
   worth seeing: with both enabled, a BARE `[do list]` is ambiguous, and
   the resolver returns a VALUE listing both candidates rather than
   guessing. A client must turn that into a prompt, never auto-pick.
   `compose.cx` shows it. ]
[feature name=owner version=\"1\"
 [summary 'Who owns the things. Rename it to your own actor noun.']

 [frames [use frame=time via=registered-at]]
 [keys   [key name=owner-id via=id]]

 [nouns
  [noun name=owner
   [field name=id type=text doc='the shared key']
   [field name=name type=text]
   [field name=registered-at type=instant]]]

 [verbs
  [verb name=register effect=act scope=shared consequence=reversible
   [intent [do :register]]
   [writes owner]]
  [verb name=list effect=observe
   [summary 'Shares its bare term with thing/list — see the header.']
   [intent [do :list]]
   [reads owner]]]

 [governance [grant verb=register to=operator]]

 [requirements
  [requirement kind=functional as=operator traces=register
   [want 'to register an owner'] [so 'things can be attributed to someone']
   [acceptance 'a registered owner appears under the /owner state route']]]]
"
}

fn xap_init_composite(name string) string {
	return "[; The COMPOSITE. This is the reason the other two are separate.

   It joins them over the shared `owner-id` key into a DERIVED noun that
   exists in neither base — a relationship between two features can only
   live above both of them.

   THE RULE PLACEMENT IS THE LESSON. 'A thing can only be created for an
   owner that was registered' is a true statement about this domain, and
   it may NOT be written in thing.feature.cxd: a base feature naming
   another feature's verb reaches outside its own grammar, W4 refuses it,
   and it would mean `thing` could never be enabled alone. It belongs
   here, because `uses` puts both bases inside this feature's reach.

   Try moving it into thing.feature.cxd and running compose.cx — the
   refusal is immediate and names the rule. ]
[feature name=thing-of-owner version=\"1\" kind=composite
 [summary 'Things joined to their owners — the view neither base can produce alone.']

 [uses features='thing owner']

 [frames [use frame=time]]
 [keys   [key name=owner-id via=owner]]

 [nouns
  [noun name=owned-thing derived=true
   [summary 'One thing with its owner resolved — derived, never sourced.']
   [field name=thing-id type=text]
   [field name=owner type=text]
   [field name=owner-name type=text]
   [field name=label type=text]
   [; the JOIN this noun means is prose — [from …] names the SOURCES, and
      join semantics are deliberately unspecified and uncomputed (#840):
        thing/thing JOIN owner/owner ON thing/thing.owner = owner/owner.id ]
   [from 'thing/thing' 'owner/owner']]]

 [verbs
  [verb name=review effect=observe
   [intent [do :review]]
   [reads owned-thing]]
  [verb name=reassign effect=act scope=shared consequence=reversible
   [summary 'DERIVED — its authority is its constituents, never its own name.']
   [intent [do :reassign]]
   [reads owned-thing]
   [writes thing]
   [constituents 'thing/create owner/register']]]

 [rules
  [rule name=create-after-register kind=ordering verb=thing/create after=owner/register
   [statement 'A thing can only be created for an owner that was registered.']]]

 [requirements
  [requirement kind=functional as=operator traces=review
   [want 'to see things with their owners resolved']
   [so 'I do not have to join them by hand']
   [acceptance 'owned-thing is present in the composed grammar as a derived noun']]
  [requirement kind=functional as=operator traces=reassign
   [want 'to reassign a thing to another owner']
   [so 'ownership can be corrected']
   [acceptance 'reassign derives its effect signature from its constituents']
   [acceptance 'a principal granted only thing-of-owner/reassign is REFUSED — the denial names the constituent']]]]
"
}

fn xap_init_xap(name string) string {
	return "[; The WIRING layer. It declares no grammar — the features already did.
   It enables them, names who has authority, declares the agent and its
   dial, and says how the thing is packaged. ]
[xap name=${name} version=\"1\"
 [summary 'Describe what this XAP is for.']

 [features
  [feature name=thing package='./thing.feature.cxd']
  [feature name=owner package='./owner.feature.cxd']
  [feature name=thing-of-owner package='./thing-of-owner.feature.cxd']]

 [principals
  [role name=operator authority=operations features='*'
   doc='The human with final authority.']
  [agent name=assistant
   doc='Proposes; does not dispose. See the dial below.']]

 [deployment model=in-process role=app]

 [surfacing default=peripheral]

 [governance
  [authority role=operator]
  [; THE DIAL at its floor: the agent may observe and propose, never
     commit an act. Raising it is one explicit, revocable delegation. ]
  [agent-default name=assistant dial=floor]]

 [requirements
  [requirement kind=domain level=must
   [statement 'The agent MUST NOT commit an irreversible verb at dial=floor.']
   [acceptance 'the assistant emitting an act verb is refused at the PEP']]]]
"
}

fn xap_init_surface(name string) string {
	mut panels := ''
	for p in xap_init_panes() {
		panels += "\n  [panel name=${p.panel} feature=${p.comp} kind=view\n" +
			'   [layout region=${p.region} mode=${p.mode}]\n' +
			'   [materialize on=screen as=table trigger=always priority=peripheral]\n' +
			"   [shows '${xap_init_shows(p)}']]"
	}
	return "[; The MATERIALIZATION layer. DERIVED from the xap + features: it BINDS
   already-declared verbs to media and lays them out. It never redeclares
   an intent — if a control here names a verb no feature declares, the
   surface is wrong, not the feature. ]
[surface name=${name}-console xap=${name} version=\"1\"
 [summary 'The operator console.']

 [media
  [medium name=screen kind=visual primary=true]]

 [panels${panels}]

 [controls
  [control intent=thing/create   [materialize on=screen as=form]]
  [control intent=owner/register [materialize on=screen as=form]]]

 [clients
  [; agent-parity: the agent attaches to the SAME surface a human does. ]
  [client kind=human attach=independent]
  [client kind=agent attach=mirrored]]]
"
}

fn xap_init_compose(name string) string {
	return "[; Compose this XAP's features through the W1-W6 gate and show what it
   produced. Run it before editing anything:

     cx --allow-read compose.cx

   NOTE the `//feature` DESCENDANT step. Each spec file opens with a
   `[; … ]` block comment, so the CHILD step `/feature` selects NOTHING.
   Composing zero features is now refused outright (CXER4874) rather than
   reported green, so this mistake fails loudly instead of quietly — but
   the selector is still the thing to get right.

   NOTE the postfix `!` on each read. Navigating an err yields the EMPTY
   node-set, not the err (code.md §6.2, normative) — so without the `!` a
   missing or misnamed file reads as a document with no features. The
   spec's own remedy is `guard the BINDING, not the query`: `!` names the
   failing FILE at the point it fails, where the compose refusal below can
   only tell you the composition ended up empty. Two guards, and they
   report different things on purpose. ]
[?lib 'cx-xap' :as xap]
[?lib 'cx-stdlib/io' :as io]
[?lib 'cx-stdlib/cx' :as cx]

[?let
  [= \$ad [\$cx:parse [\$io:read-file 'thing.feature.cxd']!]]
  [= \$bd [\$cx:parse [\$io:read-file 'owner.feature.cxd']!]]
  [= \$cd [\$cx:parse [\$io:read-file 'thing-of-owner.feature.cxd']!]]
  [= \$a  [\$first [?for [in \$n \$ad//feature] [yield \$n]]]]
  [= \$b  [\$first [?for [in \$n \$bd//feature] [yield \$n]]]]
  [= \$c  [\$first [?for [in \$n \$cd//feature] [yield \$n]]]]
  [= \$g  [\$xap:compose \$a \$b \$c]]
  [= \$g1 [\$xap:compose \$a]]
  [; #853 — a computed [err] in element CHILD position PROPAGATES (code.md
     §6.4.1), so an ambiguity/unknown VALUE cannot be embedded as a child.
     Bind it and read its parts: path navigation does not propagate. ]
  [= \$amb [\$xap:resolve \$g 'list']]
  [= \$unk [\$xap:resolve \$g 'nosuchverb']]

  [${name}
    [gate [\$xap:compose-report \$a \$b \$c]]
    [grammar verbs=[\$count \$g//verb] nouns=[\$count \$g//noun]
             hash=[\$xap:grammar-hash \$g]]
    [resolution
      [unique-owner    [\$xap:resolve \$g 'create']]
      [qualified-wins  [\$xap:resolve \$g 'thing/list']]
      [; both bases define a bare `list`, so this is an ambiguity VALUE
         listing both candidates — a prompt, never a guess ]
      [ambiguous       code=\$amb@code candidates=\$amb@candidates]
      [unknown         code=\$unk@code]]
    [; enabling a feature may only ever turn a resolution into a prompt
       that STILL LISTS the old answer — never into a different verb ]
    [no-silent-rebinding
      [with-thing-alone [\$xap:resolve \$g1 'list']]
      [with-owner-too   code=\$amb@code candidates=\$amb@candidates]]]]
"
}

fn xap_init_readme(name string) string {
	return "# ${name}

A XAP scaffolded by `cx xap init`. Three authored layers, and they compose
as generated — nothing to fix before it runs.

| File | Layer |
|---|---|
| `thing.feature.cxd` | base feature |
| `owner.feature.cxd` | base feature — registers the same key |
| `thing-of-owner.feature.cxd` | **composite** — joins them, derives a noun neither has |
| `${name}.xap.cxd` | wiring: features enabled, principals, the agent's dial |
| `${name}.surface.cxd` | materialization: verbs bound to media |

```bash
cx --allow-read compose.cx
```

## Three things the skeleton is trying to show you

**A composite is a feature nobody authored the data for.** `owned-thing`
is in neither base — a relationship between two features can only live
above both.

**Features stay independent, and the gate enforces it.** The rule \"a thing
can only be created for an owner that was registered\" is on the
*composite*, not on `thing`. Move it into `thing.feature.cxd` and compose
again: W4 refuses it, because a base naming another feature's verb would
mean `thing` could never be enabled alone.

**Ambiguity is a value, not a guess.** Both bases define a bare `list`.
With both enabled, `[do list]` returns a value listing both candidates. A
client turns that into a prompt; it may not auto-pick. The same pair shows
that enabling a feature never silently changes what an existing utterance
meant.

## Next

- Rename the nouns and verbs to your domain; the shapes carry over.
- Add a component per feature (`bind`, `emits`, and a view) to run the
  cascade — PEP → journal → ordered bus, with state as the fold.
- A client is a SEPARATE project (`cx xap init ${name} --client` scaffolds
  a RUNNABLE one — generic tables derived from the surface's `shows`, a
  floor for your own views): a XAP never embeds its renderer.
"
}

fn xap_init_client_files(name string) map[string]string {
	return {
		'client.cxd':        xap_init_client_spec(name)
		'serve.cx':          xap_init_client_serve(name)
		'shell/layout.html': xap_init_client_shell(name)
		'README.md':         xap_init_client_readme(name)
	}
}

fn xap_init_client_readme(name string) string {
	return '# ${name}-web-client\n\n' +
		'A SEPARATE project from the XAP (N-CLIENT-2): a XAP never embeds its\n' +
		'renderer. It exposes the surface as data; this materializes it into one\n' +
		'medium. The same surface drives a CLI, a TUI, an agent and a browser with\n' +
		'no change to the XAP.\n\n' +
		'## It RUNS as generated\n\n' +
		'```bash\n' +
		'cd ${name}-web-client\n' +
		'cx --allow-read --allow-env --allow-net=127.0.0.1:8791 serve.cx\n' +
		'# then open http://127.0.0.1:8791/\n' +
		'```\n\n' +
		'`CX_XAP_DIR` (default `../${name}`) and `CX_XAP_PORT` (default `8791`)\n' +
		'override where the XAP\'s feature files are read from and where it binds.\n\n' +
		'## The tables are a FLOOR — replace them\n\n' +
		'Every pane you see is a GENERIC TABLE derived from the surface\'s\n' +
		'`[shows …]` declarations: every shown field a column, no view authored\n' +
		'by hand. That is deliberately the least presentation that is still a\n' +
		'working surface — the starting point you replace with views in your own\n' +
		'medium, never a lesson in final UX. `reference/shop-web-client/serve.cx`\n' +
		'in the cx repo shows authored views over the same machinery.\n\n' +
		'What is here:\n\n' +
		'| File | Role |\n' +
		'|---|---|\n' +
		'| `client.cxd` | the client SPEC (validates against `client.cxs`) |\n' +
		'| `serve.cx` | the server: components + generic table views + `[\$xap:serve]` |\n' +
		'| `shell/layout.html` | the document shell the panes land inside |\n\n' +
		'Every button posts to `POST /intent/<verb>`; a verb outside the declared\n' +
		'vocabulary is refused with 403 before anything commits. Each pane polls\n' +
		'`GET /<bind>` for its re-rendered fragment on the cadence `client.cxd`\n' +
		'declares. The composite pane\'s rows are committed at boot by the `join`\n' +
		'deriver over the seed data — a live deriver (re-deriving on every\n' +
		'commit) is yours to add when you replace the floor.\n'
}

// xap_init_client_component renders one [$xap:component …] block whose view
// is the GENERIC TABLE derived from the pane's shown fields (RULED: ATC-2):
// every shown field a column, no view authored by hand.
fn xap_init_client_component(p XapInitPane) string {
	mut head := ''
	for f in p.fields {
		head += "[cell '${f}'] "
	}
	mut cells := ''
	for f in p.fields {
		cells += "\n                             [cell [\$concat '' [?else \$r/${f} '']]]"
	}
	mut emits := ''
	if p.verb != '' {
		mut slots := ''
		for s in p.slots {
			slots += ' [${s} :string]'
		}
		emits = '\n   emits: ([do :${p.verb}${slots}])'
	}
	mut control := ''
	if p.verb != '' {
		mut inputs := ''
		for s in p.slots {
			inputs += ' [input :${s}]'
		}
		control = "\n             [control :${p.verb} [label '${p.label}']${inputs}]"
	}
	return '[\$xap:component ${p.comp}\n' +
		'  {bind: "${p.bind}"${emits}\n' +
		'   view: [?fn (\$rs)\n' +
		'           [panel\n' +
		'             [table\n' +
		'               [head ${head.trim_space()}]\n' +
		'               [?for [in \$r \$rs]\n' +
		'                 [yield [row${cells}]]]]${control}]]\n' +
		'   working-panel: :none}]\n'
}

// xap_init_client_serve renders the client's GENERATED server (RULED:
// ATC-2): one component per pane, each view the generic `shows` table, the
// composite pane's rows committed through the bound deriver, then
// [$xap:serve] over the composed grammar. It mirrors the authored exemplar
// (reference/shop-web-client/serve.cx) shape for shape.
fn xap_init_client_serve(name string) string {
	mut comps := ''
	for p in xap_init_panes() {
		comps += xap_init_client_component(p) + '\n'
	}
	return "[; ${name}-web-client/serve.cx — the client's server, GENERATED by
   `cx xap init --client`.

     cx --allow-read --allow-env --allow-net=127.0.0.1:8791 serve.cx

   Run it from THIS directory: it reads the XAP's feature files from
   '../${name}' and the document shell from './shell'. CX_XAP_DIR and
   CX_XAP_PORT override both.

   THE VIEWS BELOW ARE A FLOOR. Each one is a GENERIC TABLE derived from
   the surface's `[shows …]` declarations — every shown field a column,
   no view authored by hand. That is deliberately the least presentation
   that is still a working surface: replace each table with a view in
   your own medium (reference/shop-web-client/serve.cx in the cx repo
   shows authored ones). A floor to build on, never a lesson in final UX.

   The server is [\$xap:serve], which already speaks hypermedia: it
   splices {{surface:NAME}} mounts into the shell, answers GET /<bind>
   with a pane's re-rendered fragment (the hx-get cadence in
   shell/layout.html), GET /surface as application/cx (agent parity),
   and routes POST /intent/<verb> through the cascade — refusing any
   verb outside the declared vocabulary with 403 before anything commits.

   This runtime is UNBOUND (no journal:): the fold is real and
   in-process, but nothing commits durably — which is what lets the
   web's anonymous intents through. Attributed durable commits over the
   web want [\$xap:host], which carries auth. ]

[?lib 'cx-xap' :as xap]
[?lib 'cx-stdlib/io' :as io]
[?lib 'cx-stdlib/cx' :as cx]
[?lib 'cx-stdlib/env' :as env]

[; the composite's join, as a def — the deriver runs the join the derived
   noun's [from …] describes (composition §4.2). Derivation happens ONCE
   at boot over the seed; a live deriver is yours to add with your views. ]
[?def owned-of scope=public pure [returns [sequence element]] (\$things \$owners)
  [?for [in \$t \$things]
    [yield [owned-thing
             [thing-id [\$concat '' [?else \$t/id '']]]
             [owner [\$concat '' [?else \$t/owner '']]]
             [owner-name [?else [\$first [?for [in \$w \$owners]
                                  [where [= [\$concat '' \$w/id] [\$concat '' \$t/owner]]]
                                  [yield [\$concat '' \$w/name]]]] '(unregistered)']]
             [label [\$concat '' [?else \$t/label '']]]]]]]

[; ── the components: one per pane, each view a generic `shows` table ── ]

${comps}[?let
  [= \$dir [?else [\$env:var 'CX_XAP_DIR'] '../${name}']]
  [= \$port [?else [\$env:var 'CX_XAP_PORT'] '8791']]

  [; compose the XAP's grammar — the client pins the SAME grammar the
     runtime enforces, so a control it renders and a verb the PEP checks
     cannot drift apart. `!` guards each BINDING: an err navigates to the
     EMPTY node-set (code.md §6.2), so an unguarded read would serve a
     surface composed from no features at all. ]
  [= \$ad [\$cx:parse [\$io:read-file [\$concat \$dir '/thing.feature.cxd']]!]]
  [= \$bd [\$cx:parse [\$io:read-file [\$concat \$dir '/owner.feature.cxd']]!]]
  [= \$cd [\$cx:parse [\$io:read-file [\$concat \$dir '/thing-of-owner.feature.cxd']]!]]
  [= \$a [\$first [?for [in \$n \$ad//feature] [yield \$n]]]]
  [= \$b [\$first [?for [in \$n \$bd//feature] [yield \$n]]]]
  [= \$c [\$first [?for [in \$n \$cd//feature] [yield \$n]]]]
  [= \$g [\$xap:compose \$a \$b \$c]]

  [; run ASSEMBLY (composition §4.2): a grammar carrying a derived noun
     refuses to assemble until its producer is bound, and the declared
     reads must sit inside the noun's [from …] envelope. ]
  [= \$rt [\$xap:run {tenant: \"${name}\" grammar: \$g
                    derivers: ({name: \"join\"
                                produces: \"thing-of-owner/owned-thing\"
                                reads: (\"thing/thing\", \"owner/owner\")})}]]

  [; ── seed: one owner, two things — the tables show data out of the box
     (the composite's ordering rule wants register before create). ]
  [= \$_1 [\$xap:emit \$rt [do :register [id \"o-1\"] [name \"ada\"]
                                       [registered-at \"2026-01-01T00:00:00Z\"]]
                        {actor: \"principal:operator\"}]]
  [= \$_2 [\$xap:emit \$rt [do :create [id \"t-1\"] [owner \"o-1\"]
                                     [created-at \"2026-01-02T00:00:00Z\"]
                                     [label \"first thing\"]]
                        {actor: \"principal:operator\"}]]
  [= \$_3 [\$xap:emit \$rt [do :create [id \"t-2\"] [owner \"o-1\"]
                                     [created-at \"2026-01-03T00:00:00Z\"]
                                     [label \"second thing\"]]
                        {actor: \"principal:operator\"}]]

  [; ── the deriver commits the join's rows — the ordinary append/fold
     path, attributable as deriver:join, the only way anything reaches
     /owned-thing (the composite has no write verb for it). ]
  [= \$rows [\$owned-of [\$xap:state \$rt \"/thing\"] [\$xap:state \$rt \"/owner\"]]]
  [; [\$count] forces the comprehension — a bound iterator is lazy, and a
     derive that never runs would serve an empty composite pane. ]
  [= \$_4 [\$count [?for [in \$r \$rows]
                   [yield [\$xap:derive \$rt {deriver: \"join\"
                                            noun: \"thing-of-owner/owned-thing\"
                                            record: \$r}]]]]]

  [\$xap:serve [\$concat 'http://127.0.0.1:' \$port]
    {runtime: \$rt
     tenant: \"${name}\"
     shell: 'shell'}]]
"
}

fn xap_init_client_spec(name string) string {
	return "[; The CLIENT SPEC — the fourth document kind, in its OWN project.
   A XAP never embeds its renderer (N-CLIENT-2), so this lives beside the
   XAP rather than inside it. The same surface data drives a CLI, a TUI,
   an agent and this web client with no change to the XAP at all. ]
[client name=${name}-web version=\"1\"
 [summary 'A hypermedia client: server-rendered CX → HTML, no JavaScript.']

 [attaches xap=${name} surface=${name}-console]

 [medium name=screen kind=visual]

 [shell dir='shell']

 [panes
  [pane panel=things refresh='every 5s']
  [pane panel=owners refresh='every 5s']
  [pane panel=owned  refresh='every 5s']]

 [controls
  [control intent=thing/create   as=form]
  [control intent=owner/register as=form]]

 [javascript policy=none
  doc='Minimal-JS-by-exception; this client takes no exception.']]
"
}

fn xap_init_client_shell(name string) string {
	// The surface mount placeholder is assembled rather than written
	// literally: the shell splicer scans the whole file, so a placeholder
	// appearing anywhere — including in a comment — is resolved as a
	// component name and refuses when there is no such component.
	o := '{{surface:'
	c := '}}'
	mut panes := ''
	for p in xap_init_panes() {
		seg := p.bind.all_after('/')
		// the hx attributes ride the SECTION and target the mount div: the
		// fragment GET /<bind> answers is the mount element itself, so a
		// swap that replaced the polling element would stop the cadence.
		panes += '  <section class="pane" hx-get="${p.bind}" hx-trigger="every 5s" ' +
			'hx-target="#${seg}-mount" hx-swap="outerHTML">\n' +
			'    <h2>${p.panel}</h2>\n' +
			'    <div id="${seg}-mount">${o}${p.comp}${c}</div>\n' + '  </section>\n\n'
	}
	return '<!doctype html>\n' +
		'<html lang="en">\n<head>\n  <meta charset="utf-8">\n' +
		'  <title>${name} console</title>\n' +
		'  <script src="https://unpkg.com/htmx.org@1.9.10"></script>\n' +
		'</head>\n<body>\n  <h1>${name}</h1>\n\n' + panes +
		'  <footer>\n' +
		'    <p>Every button posts to /intent/&lt;verb&gt;; a verb outside the\n' +
		'    declared vocabulary is refused with 403 before anything commits.\n' +
		'    These tables are the generic floor derived from the surface\'s\n' +
		'    shows declarations — replace them with your own views.</p>\n' +
		'  </footer>\n' +
		'</body>\n</html>\n'
}
