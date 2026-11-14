// Check a partner site's agent network before this site calls it.
//
// Usage:
//   node check_partner.mjs <partner network URL> [--origin <this site's origin>]
//
// It reads only the partner's public files, the way a calling browser reads them: the
// manifest, the network file, links.json and the action bridge. It checks that each one
// loads with the headers a browser needs, then prints what the partner's network can
// reach and what to add to this site. It exits with code 1 when it finds errors.

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sameOriginAsset } from "../runtime/action-transport.js";
import { parseHocon } from "../runtime/hocon.js";
import { AgentNetwork, parseExternalAgent, validateNetwork } from "../runtime/kernel.js";
import { resolveUrl } from "../runtime/remote.js";
import { requiresThirdPartyApproval, safeName } from "../runtime/runner.js";

/**
 * Checks one partner network URL with the skill's own runtime.
 *
 * Node's fetch does not enforce CORS, so every request sends the caller's Origin header,
 * and the check reads Access-Control-Allow-Origin itself. It follows redirects on the
 * partner's origin, as the runtime does, and stops at a redirect to another origin.
 */
export class PartnerCheck {
  /**
   * Hosts where a partner may use http. Every other host needs https.
   */
  static LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

  /**
   * The Origin sent without --origin. It stands for any other site; .example is never a real site.
   */
  static ANY_SITE = "https://caller.example";

  /**
   * The most same-origin redirects to follow for one file.
   */
  static MAX_REDIRECTS = 5;

  /**
   * The start of the template's peer rule. Without it, a network run with no website_*
   * tools follows the runtime's note to report a missing integration.
   */
  static PEER_RULE = "When you have no website_* tools, another site's assistant is asking";

  /**
   * The longest start of the partner's instructions to print, in characters.
   */
  static OPENING_LENGTH = 300;

  /**
   * The usage line, printed after a bad argument.
   */
  static USAGE = "Usage: node check_partner.mjs <partner network URL> [--origin <this site's origin>]";

  /**
   * Store the options, the fetch to use and where to print.
   *
   * :param options: Parsed options with url and origin.
   * :param fetchImpl: The fetch function, such as the global fetch, or a stand-in in tests.
   * :param print: A function that prints one line.
   */
  constructor(options, fetchImpl, print) {
    this.options = options;
    this.fetch = fetchImpl;
    this.print = print;
    this.errors = [];
    this.warnings = [];
    // The Origin header for every request: this site's origin, or a stand-in for any site.
    this.origin = options.origin || PartnerCheck.ANY_SITE;
  }

  /**
   * Parse command-line arguments into an options object.
   *
   * :param argv: The arguments after the script name.
   * :return: The options object.
   * :raises Error: When the URL is missing, an option has no value or --origin is not an origin.
   */
  static parseArgs(argv) {
    const options = {
      url: null,
      origin: null,
    };
    let index = 0;
    while (index < argv.length) {
      const arg = argv[index];
      if (arg === "--origin") {
        const value = argv[index + 1];
        if (value === undefined) {
          throw new Error("--origin needs a value.");
        }
        options.origin = value;
        index += 1;
      } else if (options.url === null) {
        options.url = arg;
      } else {
        throw new Error(`Unexpected argument: ${arg}`);
      }
      index += 1;
    }
    if (options.url === null) {
      throw new Error(PartnerCheck.USAGE);
    }
    if (options.origin !== null) {
      const origin = PartnerCheck.originOf(options.origin);
      if (origin === null) {
        throw new Error(`--origin needs this site's origin, such as http://localhost:8081, not "${options.origin}".`);
      }
      options.origin = origin;
    }
    return options;
  }

  /**
   * Run the check and print a report.
   *
   * :param argv: The arguments after the script name.
   * :param fetchImpl: The fetch function to use for every request.
   * :param print: A function that prints one line.
   * :return: The process exit code: 0 when there are no errors, 1 with errors, 2 on a bad argument.
   */
  static async main(argv, fetchImpl, print) {
    let options;
    try {
      options = PartnerCheck.parseArgs(argv);
    } catch (error) {
      print(error.message);
      return 2;
    }
    const check = new PartnerCheck(options, fetchImpl, print);
    try {
      return await check.run();
    } catch (error) {
      print(`Check failed: ${error.message}`);
      return 2;
    }
  }

  /**
   * Say whether node started this file as its script, rather than a test importing it.
   *
   * :param moduleUrl: This module's import.meta.url.
   * :return: True when this file is the script node was started with.
   */
  static isScript(moduleUrl) {
    if (!process.argv[1]) {
      return false;
    }
    // Compare real paths, so a skill folder reached through a link still runs.
    try {
      return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(moduleUrl));
    } catch (error) {
      return false;
    }
  }

  /**
   * Check the partner, print what it can reach and what to add, then the findings.
   *
   * :return: 1 when there are errors, otherwise 0.
   */
  async run() {
    this.print(`Partner network: ${this.options.url}`);
    if (this.options.origin) {
      this.print(`Caller origin: ${this.origin}`);
    } else {
      this.print("Caller origin: any site. Pass --origin <this site's origin> to check yours.");
    }
    const target = this.checkUrl();
    // A page reads files on its own origin without any CORS header, so that check would pass.
    if (target !== null && this.options.origin && this.origin === target.origin) {
      this.warnings.push("--origin is the partner's own origin, so no CORS header is checked. Leave out --origin, or pass another site's origin.");
    }
    if (target !== null) {
      await this.checkPartner(target);
    }
    return this.report();
  }

  /**
   * Check the URL's form, the way the runtime reads it.
   *
   * :return: The URL's parts (url, origin, folder, name and toolName), or null when it is unusable.
   */
  checkUrl() {
    const ref = this.options.url;
    let url = null;
    try {
      url = new URL(ref);
    } catch (error) {
      url = null;
    }
    if (url === null || (url.protocol !== "http:" && url.protocol !== "https:")) {
      this.errors.push(`${ref} is not a full http or https URL. Give the folder that holds the partner's agent-manifest.json, then its network name, such as https://partner.example/partner_network.`);
      return null;
    }
    if (url.pathname.endsWith("/") || ref.includes("?") || ref.includes("#")) {
      this.errors.push(`${ref} must end in the network name, with no "/" at the end, no query and no "#", such as https://partner.example/partner_network.`);
      return null;
    }
    if (url.protocol === "http:" && !PartnerCheck.LOOPBACK_HOSTS.includes(url.hostname)) {
      this.errors.push(`${ref} uses http. Use https for every host but localhost and 127.0.0.1.`);
    }
    const segments = url.pathname.split("/");
    // The runtime reads the manifest from the folder before the last path segment, and
    // runs only the network that segment names (runtime/engine.js, resolveRemote).
    return {
      url: ref,
      origin: url.origin,
      folder: new URL("./", url).href.replace(/\/$/, ""),
      name: segments[segments.length - 1],
      // The model and the consent card see the tool under this name (runtime/runner.js, buildToolTable).
      toolName: safeName(parseExternalAgent(ref, url.origin).agentName),
    };
  }

  /**
   * Read and check the partner's public files, then print what its network can reach and
   * what to add to this site.
   *
   * :param target: The URL's parts from checkUrl.
   */
  async checkPartner(target) {
    const manifest = await this.readManifest(target);
    if (manifest === null) {
      return;
    }
    const entry = this.findNetwork(manifest, target);
    if (entry === null) {
      return;
    }
    const network = await this.readNetwork(entry, target);
    const links = await this.readLinks(target);
    await this.checkBridge(manifest, target);
    if (network !== null) {
      this.printReach(network, manifest, target, links);
    }
    if (!this.errors.length) {
      this.printAdditions(manifest, target);
    }
  }

  /**
   * Fetch one public file the way a calling browser asks for it.
   *
   * :param url: The file's URL.
   * :param what: The file's name in messages, such as "The manifest".
   * :return: The final url, the response and its text, or null when it could not be fetched.
   */
  async get(url, what) {
    let current = new URL(url).href;
    for (let hop = 0; hop <= PartnerCheck.MAX_REDIRECTS; hop += 1) {
      let response = null;
      try {
        response = await this.fetch(current, {
          headers: {
            Origin: this.origin,
          },
          redirect: "manual",
        });
      } catch (error) {
        this.errors.push(`${what} at ${current} cannot be fetched: ${PartnerCheck.reason(error)}.`);
        return null;
      }
      const location = response.headers.get("location");
      if (response.status < 300 || response.status > 399 || !location) {
        const text = await response.text();
        this.print(`Read: ${current} (${response.status})`);
        return {
          url: current,
          response: response,
          text: text,
        };
      }
      const next = new URL(location, current).href;
      if (new URL(next).origin !== new URL(current).origin) {
        this.errors.push(`${what} at ${current} redirects to another origin: ${next}.`);
        return null;
      }
      this.warnings.push(`${what} at ${current} redirects to ${next}. The runtime follows it.`);
      current = next;
    }
    this.errors.push(`${what} at ${url} redirects more than ${PartnerCheck.MAX_REDIRECTS} times.`);
    return null;
  }

  /**
   * Say why a browser on the caller's origin could not read a file, if it could not.
   *
   * :param file: A fetched file from get().
   * :return: The problem, or null when the CORS header allows the caller.
   */
  corsProblem(file) {
    // A page on the same origin reads the file without any CORS header.
    if (new URL(file.url).origin === this.origin) {
      return null;
    }
    const allowed = file.response.headers.get("access-control-allow-origin");
    if (allowed === null) {
      return "sends no Access-Control-Allow-Origin header, so a browser on another site cannot read it and the call fails with \"Failed to fetch\"";
    }
    if (allowed.trim() === "*" || allowed.trim() === this.origin) {
      return null;
    }
    if (this.options.origin) {
      return `sends Access-Control-Allow-Origin "${allowed}", which leaves out ${this.origin}, so the call fails with "Failed to fetch"`;
    }
    return `sends Access-Control-Allow-Origin "${allowed}", which does not allow every site. Pass --origin <this site's origin> to check yours`;
  }

  /**
   * Fetch and parse the partner's agent-manifest.json.
   *
   * :param target: The URL's parts from checkUrl.
   * :return: The manifest, or null when it cannot be used.
   */
  async readManifest(target) {
    const file = await this.get(`${target.folder}/agent-manifest.json`, "The manifest");
    if (file === null) {
      return null;
    }
    if (file.response.status !== 200) {
      this.errors.push(`The manifest at ${file.url} answered ${file.response.status}, not 200. The folder before the network name must hold agent-manifest.json.`);
      return null;
    }
    const problem = this.corsProblem(file);
    if (problem !== null) {
      this.errors.push(`The manifest at ${file.url} ${problem}.`);
    }
    return this.parseJson(file, "The manifest");
  }

  /**
   * Parse a fetched file as a JSON object.
   *
   * :param file: A fetched file from get().
   * :param what: The file's name in messages.
   * :return: The object, or null when the text is not a JSON object.
   */
  parseJson(file, what) {
    let value = null;
    try {
      value = JSON.parse(file.text);
    } catch (error) {
      this.errors.push(`${what} at ${file.url} is not valid JSON: ${error.message}`);
      return null;
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      this.errors.push(`${what} at ${file.url} is not a JSON object.`);
      return null;
    }
    return value;
  }

  /**
   * Find the manifest's entry for the network the URL names.
   *
   * :param manifest: The partner's manifest.
   * :param target: The URL's parts from checkUrl.
   * :return: The entry, or null when no network has that exact name.
   */
  findNetwork(manifest, target) {
    const networks = Array.isArray(manifest.networks) ? manifest.networks : [];
    const names = [];
    for (const entry of networks) {
      const name = entry !== null && typeof entry === "object" && typeof entry.name === "string" ? entry.name : "";
      if (name === target.name) {
        return entry;
      }
      if (name) {
        names.push(name);
      }
    }
    this.errors.push(`The manifest lists no network named "${target.name}", and a caller never runs another one. It lists: ${names.length ? names.join(", ") : "none"}.`);
    return null;
  }

  /**
   * Fetch the network file and check it as a caller's runtime would before running it.
   *
   * :param entry: The manifest's entry for the network.
   * :param target: The URL's parts from checkUrl.
   * :return: The runtime AgentNetwork, or null when the file cannot be used.
   */
  async readNetwork(entry, target) {
    if (typeof entry.hocon !== "string" || !entry.hocon) {
      this.errors.push(`The manifest's entry for "${target.name}" names no network file in "hocon".`);
      return null;
    }
    const url = new URL(resolveUrl(target.folder, entry.hocon)).href;
    if (new URL(url).origin !== target.origin) {
      this.warnings.push(`The network file comes from another origin: ${url}. That origin decides what the partner's agents are told.`);
    }
    const file = await this.get(url, "The network file");
    if (file === null) {
      return null;
    }
    if (file.response.status !== 200) {
      this.errors.push(`The network file at ${file.url} answered ${file.response.status}, not 200.`);
      return null;
    }
    const problem = this.corsProblem(file);
    if (problem !== null) {
      this.errors.push(`The network file at ${file.url} ${problem}.`);
    }
    let config = null;
    try {
      config = parseHocon(file.text);
    } catch (error) {
      this.errors.push(`The network file at ${file.url} does not parse, so a caller refuses to run it: ${error.message}`);
      return null;
    }
    const network = new AgentNetwork(config, entry.name);
    // A caller refuses to run a network with validation errors (runtime/engine.js, _compile).
    for (const message of validateNetwork(network).errors) {
      this.errors.push(`The network file fails the runtime's validation, so a caller refuses to run it: ${message}`);
    }
    return network;
  }

  /**
   * Fetch links.json and return this network's bound links.
   *
   * The runtime ignores a links.json it cannot read, so problems here are warnings.
   *
   * :param target: The URL's parts from checkUrl.
   * :return: The links, from reference to URL.
   */
  async readLinks(target) {
    const file = await this.get(`${target.folder}/links.json`, "links.json");
    if (file === null || file.response.status === 404) {
      return {};
    }
    if (file.response.status !== 200) {
      this.warnings.push(`links.json at ${file.url} answered ${file.response.status}. The runtime then ignores it.`);
      return {};
    }
    const problem = this.corsProblem(file);
    if (problem !== null) {
      this.warnings.push(`links.json at ${file.url} ${problem}. The runtime then ignores it.`);
      return {};
    }
    let doc = null;
    try {
      doc = JSON.parse(file.text);
    } catch (error) {
      this.warnings.push(`links.json at ${file.url} is not valid JSON. The runtime then ignores it.`);
      return {};
    }
    const networks = doc !== null && typeof doc === "object" ? doc.networks || {} : {};
    const links = networks[target.name];
    return links !== null && typeof links === "object" ? links : {};
  }

  /**
   * Check the action bridge that a caller loads in a hidden frame before it runs the network.
   *
   * It works for the bridge next to the manifest and for the skill's bridge/ folder: both
   * read the agent-manifest.json in the bridge page's own folder.
   *
   * :param manifest: The partner's manifest.
   * :param target: The URL's parts from checkUrl.
   */
  async checkBridge(manifest, target) {
    const actions = manifest.actions;
    // Without actions, a caller loads no bridge (runtime/action-transport.js, registerRemoteActions).
    if (actions === null || typeof actions !== "object") {
      return;
    }
    if (actions.version !== 1) {
      this.errors.push(`The manifest's actions.version is ${JSON.stringify(actions.version)}, so a caller's runtime refuses the partner. It must be 1.`);
      return;
    }
    if (!actions.bridge) {
      this.errors.push("The manifest has actions but no actions.bridge. A caller then waits 10 seconds, asks its visitor to open a popup, and the network never runs.");
      return;
    }
    let bridgeUrl = null;
    try {
      bridgeUrl = sameOriginAsset(target.folder, String(actions.bridge));
    } catch (error) {
      this.errors.push(`actions.bridge "${actions.bridge}" is not on the partner's own origin, so a caller's runtime refuses it.`);
      return;
    }
    const page = await this.get(bridgeUrl, "The bridge page");
    if (page === null) {
      return;
    }
    if (page.response.status !== 200) {
      this.errors.push(`The bridge page at ${page.url} answered ${page.response.status}, not 200. A caller then waits 10 seconds and the network never runs.`);
      return;
    }
    const frameOptions = page.response.headers.get("x-frame-options");
    if (frameOptions !== null) {
      this.errors.push(`The bridge page at ${page.url} sends X-Frame-Options "${frameOptions}", so other sites cannot load it in a frame.`);
    }
    const policy = page.response.headers.get("content-security-policy");
    if (policy !== null && !PartnerCheck.framingAllowed(policy, this.origin, new URL(page.url).origin)) {
      const who = this.options.origin ? this.origin : "other sites";
      this.errors.push(`The bridge page at ${page.url} sends a frame-ancestors policy that leaves out ${who}, so they cannot load it in a frame.`);
    }
    await this.checkBridgeScripts(page);
    await this.checkBridgeManifest(page);
  }

  /**
   * Check that the bridge page loads at least one module script, served as JavaScript.
   *
   * :param page: The fetched bridge page from get().
   */
  async checkBridgeScripts(page) {
    const sources = PartnerCheck.moduleScripts(page.text);
    if (!sources.length) {
      this.errors.push(`The bridge page at ${page.url} loads no module script, so it never answers a caller.`);
      return;
    }
    for (const source of sources) {
      const script = await this.get(new URL(source, page.url).href, "The bridge script");
      if (script === null) {
        continue;
      }
      if (script.response.status !== 200) {
        this.errors.push(`The bridge script at ${script.url} answered ${script.response.status}, not 200.`);
        continue;
      }
      // Browsers run a module script only when it is served with a JavaScript type.
      const type = script.response.headers.get("content-type") || "";
      if (!/javascript|ecmascript/i.test(type)) {
        this.errors.push(`The bridge script at ${script.url} is served as "${type}". Browsers run module scripts only with a JavaScript type, such as text/javascript.`);
      }
    }
  }

  /**
   * Check the agent-manifest.json in the bridge page's folder, which the bridge reads first.
   *
   * :param page: The fetched bridge page from get().
   */
  async checkBridgeManifest(page) {
    const file = await this.get(new URL("./agent-manifest.json", page.url).href, "The bridge's manifest");
    if (file === null) {
      return;
    }
    if (file.response.status !== 200) {
      this.errors.push(`The bridge's manifest at ${file.url} answered ${file.response.status}, not 200, so the bridge stops before it answers a caller.`);
      return;
    }
    const manifest = this.parseJson(file, "The bridge's manifest");
    if (manifest === null) {
      return;
    }
    const first = Array.isArray(manifest.networks) ? manifest.networks[0] : null;
    if (first === null || first === undefined || typeof first.name !== "string" || !first.name) {
      this.errors.push(`The bridge's manifest at ${file.url} has no networks[0].name, so the bridge stops before it answers a caller.`);
    }
    if (manifest.actions !== undefined && manifest.actions !== null && manifest.actions.version !== 1) {
      this.errors.push(`The bridge's manifest at ${file.url} has actions.version ${JSON.stringify(manifest.actions.version)}, so the bridge stops before it answers a caller. It must be 1.`);
    }
  }

  /**
   * List the src of each module script in a page.
   *
   * :param html: The page's HTML.
   * :return: The src values, in page order.
   */
  static moduleScripts(html) {
    const sources = [];
    for (const tag of html.matchAll(/<script\b([^>]*)>/gi)) {
      const attributes = `${tag[1]} `;
      if (!/\btype\s*=\s*["']?module["'\s]/i.test(attributes)) {
        continue;
      }
      const src = attributes.match(/\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/i);
      if (src) {
        sources.push(src[1] || src[2] || src[3]);
      }
    }
    return sources;
  }

  /**
   * Say whether a Content-Security-Policy header lets the caller frame the page.
   *
   * Several policies arrive joined by commas, and a frame must pass each one. A policy
   * without frame-ancestors does not limit framing.
   *
   * :param header: The Content-Security-Policy header.
   * :param origin: The caller's origin.
   * :param pageOrigin: The bridge page's origin, which 'self' means.
   * :return: True when every policy allows the caller's origin.
   */
  static framingAllowed(header, origin, pageOrigin) {
    for (const policy of header.split(",")) {
      for (const directive of policy.split(";")) {
        const parts = directive.trim().split(/\s+/);
        if (parts[0].toLowerCase() !== "frame-ancestors") {
          continue;
        }
        if (!PartnerCheck.sourcesAllow(parts.slice(1), origin, pageOrigin)) {
          return false;
        }
        // Only the first frame-ancestors directive of a policy counts.
        break;
      }
    }
    return true;
  }

  /**
   * Say whether a frame-ancestors source list allows an origin.
   *
   * :param sources: The source expressions, such as 'self' or https://*.example.com.
   * :param origin: The caller's origin.
   * :param pageOrigin: The bridge page's origin, which 'self' means.
   * :return: True when one source matches the origin.
   */
  static sourcesAllow(sources, origin, pageOrigin) {
    const caller = new URL(origin);
    const page = new URL(pageOrigin);
    for (const raw of sources) {
      const source = raw.toLowerCase();
      if (source === "*") {
        return true;
      }
      if (source === "'self'") {
        if (origin === pageOrigin) {
          return true;
        }
        continue;
      }
      // A scheme source such as "https:". An http source also allows https.
      if (/^[a-z][a-z0-9+.-]*:$/.test(source)) {
        if (caller.protocol === source || (source === "http:" && caller.protocol === "https:")) {
          return true;
        }
        continue;
      }
      const match = source.match(/^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|\*\.[^/:]+|[^/:*]+)(?::(\d+|\*))?(?:\/.*)?$/);
      if (match === null) {
        continue;
      }
      // Without a scheme, a source means the page's own scheme.
      const scheme = match[1] ? `${match[1]}:` : page.protocol;
      const schemeOk = caller.protocol === scheme || (scheme === "http:" && caller.protocol === "https:");
      const host = match[2];
      let hostOk = caller.hostname === host || host === "*";
      if (host.startsWith("*.")) {
        hostOk = caller.hostname.endsWith(host.slice(1));
      }
      // URL.port is empty for the scheme's default port. A source without a port means that port.
      const port = match[3];
      const callerPort = caller.port || (caller.protocol === "https:" ? "443" : "80");
      const portOk = port === "*" || (port === undefined ? caller.port === "" : callerPort === port);
      if (schemeOk && hostOk && portOk) {
        return true;
      }
    }
    return false;
  }

  /**
   * Print what the partner's network can reach, and warn on what leaves the site unseen.
   *
   * :param network: The partner's runtime AgentNetwork.
   * :param manifest: The partner's manifest.
   * :param target: The URL's parts from checkUrl.
   * :param links: The partner's bound links from links.json.
   */
  printReach(network, manifest, target, links) {
    const front = network.findFrontMan();
    const instructions = String((network.getAgentSpec(front) || {}).instructions || "");
    this.print("");
    this.print("What the partner's network can reach. It runs in this site's visitor's browser, on the visitor's key, and its instructions read every request.");
    this.print("It gets none of the partner's website_* tools, so it answers only from its instructions.");
    // A caller learns little more than this, so the owner can see what the partner can answer.
    this.print(`Its front agent's instructions start: "${PartnerCheck.opening(instructions)}"`);
    if (!instructions.includes(PartnerCheck.PEER_RULE)) {
      this.warnings.push("The partner's front agent has no peer rule. With no website_* tools, the runtime's note tells it to report a missing integration, so it may answer only that.");
    }
    // The runtime's partner context sets the model and step limit (runtime/engine.js, _makeCtx).
    this.print("It runs on the visitor's model, or else this site's front-agent model, within this site's step limit. Below are the models it names:");
    const agents = Array.isArray(network.config.tools) ? network.config.tools : [];
    for (const agent of agents) {
      // Coded and REST tools are listed under the agents that call them.
      if (typeof agent.instructions !== "string") {
        continue;
      }
      const model = String((agent.llm_config || {}).model_name || "").trim() || "none";
      const steps = agent.max_steps || network.config.max_steps || 12;
      const role = agent.name === front ? " (front agent)" : "";
      this.print(`  - ${agent.name}${role}: model ${model}, max_steps ${steps}`);
      let reaches = 0;
      const tools = Array.isArray(agent.tools) ? agent.tools : [];
      for (const ref of tools) {
        const line = this.describeTool(network, agent.name, ref, target, links);
        if (line !== null) {
          this.print(`      ${line}`);
          reaches += 1;
        }
      }
      if (!reaches) {
        this.print("      nothing beyond the partner's own agents");
      }
    }
    const coded = manifest.coded_tools || {};
    if (typeof coded.bundle === "string" && coded.bundle) {
      const bundle = new URL(resolveUrl(target.folder, coded.bundle)).href;
      this.print(`  Coded-tool bundle: ${bundle}`);
      if (new URL(bundle).origin !== target.origin) {
        this.warnings.push(`The coded-tool bundle comes from another origin: ${bundle}. That origin's code runs in this site's visitor's browser.`);
      }
    }
    const references = Object.keys(links);
    if (!references.length) {
      this.print("  links.json: none");
    }
    for (const reference of references) {
      this.print(`  links.json: ${reference} -> ${links[reference]}`);
    }
  }

  /**
   * Describe one tool of a partner agent, when it reaches outside the partner's network.
   *
   * :param network: The partner's runtime AgentNetwork.
   * :param agentName: The agent that lists the tool.
   * :param ref: The tool reference.
   * :param target: The URL's parts from checkUrl.
   * :param links: The partner's bound links from links.json.
   * :return: One line, or null for the partner's own agents.
   */
  describeTool(network, agentName, ref, target, links) {
    const kind = network.classifyTool(ref).kind;
    // In a partner's run, the runtime asks the visitor only about origins other than the
    // partner's own (runtime/runner.js, requiresThirdPartyApproval).
    const asks = requiresThirdPartyApproval(ref, target.folder);
    const consent = asks ? " (asks the visitor first)" : " (on the partner's own origin: no consent card)";
    if (kind === "remote") {
      // The runtime skips a network already in the call chain (runtime/runner.js,
      // remoteIsInChain), so a call back to the caller shows no card.
      if (this.options.origin && PartnerCheck.originOf(String(ref)) === this.origin) {
        return `partner network ${ref} (on this site's origin: if it is this site's own network at a domain root, the runtime skips this call back)`;
      }
      return `partner network ${ref}${consent}`;
    }
    if (kind === "mcp") {
      const url = typeof ref === "string" ? ref : String((ref || {}).url || "");
      if (!asks) {
        this.warnings.push(`${agentName} can send requests to ${url}, an MCP server on the partner's own origin, with no consent card.`);
      }
      return `MCP server ${url}${consent}`;
    }
    if (kind === "coded") {
      return `coded tool ${ref}, which runs the partner's code in a sandbox`;
    }
    if (kind === "toolbox") {
      const args = (network.getAgentSpec(ref) || {}).args || {};
      return `REST tool ${ref}: ${String(args.method || "GET").toUpperCase()} ${args.url || "(no URL)"}`;
    }
    if (kind === "link") {
      const bound = Object.hasOwn(links, ref) ? links[ref] : network.getLink(ref);
      if (bound) {
        this.warnings.push(`${agentName} uses link slot "${ref}", which links.json binds to ${bound}. A bound slot allows that origin for the whole page.`);
        return `link slot ${ref}, bound to ${bound}`;
      }
      this.warnings.push(`${agentName} uses link slot "${ref}": an unbound slot makes this site's chat ask the visitor for a URL.`);
      return `link slot ${ref}, not bound`;
    }
    return null;
  }

  /**
   * Return the first line of some instructions, cut to OPENING_LENGTH characters.
   *
   * :param instructions: The front agent's expanded instructions.
   * :return: The first line that has text, or "" when there is none.
   */
  static opening(instructions) {
    for (const line of instructions.split("\n")) {
      const text = line.trim();
      if (text.length > PartnerCheck.OPENING_LENGTH) {
        return `${text.slice(0, PartnerCheck.OPENING_LENGTH)}…`;
      }
      if (text) {
        return text;
      }
    }
    return "";
  }

  /**
   * Print what to add to this site to call the partner. Without --origin, the check is of
   * this site's own network, so the lines are for a site that calls it.
   *
   * :param manifest: The partner's manifest.
   * :param target: The URL's parts from checkUrl.
   */
  printAdditions(manifest, target) {
    const brand = typeof manifest.brand === "string" ? manifest.brand.trim() : "";
    this.print("");
    this.print(this.options.origin ? "Add to this site:" : "A site that calls this network adds:");
    this.print(`  allowed_peers in agent-manifest.json: ${JSON.stringify(target.origin)}`);
    this.print(`  tools of the calling agent: ${JSON.stringify(target.url)}`);
    this.print(`  link_labels in the .hocon: ${JSON.stringify(target.url)}: ${JSON.stringify(brand || target.name)} (suggested; write your own)`);
    this.print(`  Tool name the model sees: ${target.toolName}`);
  }

  /**
   * Print the warnings and errors, then the result.
   *
   * :return: 1 when there are errors, otherwise 0.
   */
  report() {
    this.print("");
    for (const warning of this.warnings) {
      this.print(`WARNING: ${warning}`);
    }
    for (const error of this.errors) {
      this.print(`ERROR: ${error}`);
    }
    if (this.errors.length) {
      this.print(`FAILED with ${this.errors.length} error(s).`);
      return 1;
    }
    const who = this.options.origin ? this.origin : "other sites";
    this.print(`OK: ${this.options.url} can be called from ${who}.`);
    return 0;
  }

  /**
   * Return the origin of an http or https URL.
   *
   * :param value: A URL or origin.
   * :return: The origin, or null when the value is not an http or https URL.
   */
  static originOf(value) {
    let url = null;
    try {
      url = new URL(String(value));
    } catch (error) {
      return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    return url.origin;
  }

  /**
   * Explain why a fetch failed, such as a refused connection.
   *
   * :param error: The error fetch threw.
   * :return: A short reason.
   */
  static reason(error) {
    const cause = error && error.cause ? error.cause : null;
    // For localhost, Node tries ::1 and 127.0.0.1 and throws an AggregateError with an
    // empty message, so the code is the only clue.
    if (cause && cause.code === "ECONNREFUSED") {
      return "nothing is listening there, so the partner's site may not be running";
    }
    if (cause && cause.message) {
      return cause.message;
    }
    return error && error.message ? error.message : String(error);
  }
}

// Run only when node starts this file, not when a test imports PartnerCheck.
if (PartnerCheck.isScript(import.meta.url)) {
  process.exitCode = await PartnerCheck.main(process.argv.slice(2), fetch, console.log);
}
