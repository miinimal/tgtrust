# Browser runtime

This folder runs the agent network in the visitor's browser. Copy it into each
agentified site, and do not change it there.

It is a copy of the [nsdeploy](https://github.com/cognizant-ai-lab/nsdeploy) browser
runtime (Apache 2.0, see `LICENSE.txt`) at nsdeploy commit `53a787c` (2026-11-11), with
the edits listed below.

Why it is edited. A site's page has its own functions, called actions, like a room
search. nsdeploy's runtime does not let an agent use them as tools. The agent can only
offer a button or form. The visitor must click it and, by default, confirm the action.
The agent cannot answer until the visitor writes again.

Without editing the runtime, a site can plug in its own confirmation dialog, but not
tools that run the page's functions: the runtime builds the tool list in its own code. So
the runtime is edited. nsdeploy has no issue or pull request for this, so the edits live
here.

With the edits, each action the site's settings file (`agent-manifest.json`) lists under
`agentTools` becomes a `website_<name>` tool. Look-ups and undoable changes, such as
filling in the booking form, run without asking. Only actions the site marks
`irreversible`, like a booking, wait for the visitor to confirm. The AI model cannot
change these marks.

Linked sites need one more edit. When this site calls a partner site's network, that
network runs in this visitor's browser and on their key. In nsdeploy's runtime, the
partner network chooses the model and how many steps it takes, so it chooses what the
visitor pays for. With the edit, it runs on the visitor's model or, if they picked none,
this site's model, within this site's step limit.

Edited files. Each one has a line near its top saying that it was changed:

- `runner.js` offers each local-only action listed in the manifest's `actions.agentTools`
  as a `website_<name>` tool and runs it through the site's action registry. Actions with
  the `irreversible` effect ask the visitor first. Only the visitor's own site gets these
  tools, never a partner network. It also adds a `render_cruse` tool for forms and tables
  in the chat. It stops a partner agent at the step limit `engine.js` passes.
- `engine.js` passes the page's confirmation dialog to `runner.js`. It also runs a partner
  network on the visitor's model or, when the visitor picked none, on this site's
  front-agent model, and passes this site's step limit, so a partner network cannot choose
  what the visitor pays for.
- `cruse.js` accepts CRUSE replies without code fences and merges forms from several
  agents into one. It also tells agents about the `render_cruse` tool.
- `ui.js` shows a time picker for `format: "time"` fields and option labels from
  `x-ui.enumLabels`. It groups radio buttons under a legend and links each field to its
  description for screen readers. The ⚙ AI model settings panel lists hosted Otari first,
  the template's default router, and fills in its settings for a key that starts with
  `otk_`.
- `action-transport.js` opens the confirmation dialog with focus on its heading, so a
  stray Enter cannot confirm an action. Closing the dialog puts focus back where it was.
- `index.js` tells visitors that only actions that cannot be undone ask first, when the
  site offers `website_*` tools.

Protocol name: `nsdeploy`. Use it for `<protocol_name>` in `agent-manifest.json`. It
names the discovery files, such as `.well-known/nsdeploy.json`, that nsdeploy's tools read.

Do not edit or replace these files for one site. This copy is for use until nsdeploy's
own runtime offers these tools and partner limits.

nsdeploy plans to move to a runtime built on the neuro-san TS package (nsdeploy PR #10).
That runtime has no `website_*` tools yet. Before a site switches to it, move the edits
above to it and check that it offers those tools and runs a partner network on the
caller's model and step limit.
