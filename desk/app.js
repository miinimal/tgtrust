// The one Desk object of this page. The page script (desk-page.js) and the site actions (site-actions.js) both
// import it from this URL, so they share one state.
import { Desk } from "./desk.js";
import { ISSUERS } from "./issuers.js";

export class App {
  static desk = new Desk({ issuers: ISSUERS });
}
