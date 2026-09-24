/**
 * CLI defaults that are quoted in `--help`.
 *
 * They live here (in a side-effect-free module) so that the value the CLI
 * actually applies and the value the help text advertises cannot drift apart:
 * tests import these constants and assert the help output matches.
 */

/** Hard cost ceiling for one autonomous campaign, in USD. */
export const DEFAULT_MAX_COST_USD = 10;

/** Maximum planner/judge iterations for one autonomous campaign. */
export const DEFAULT_MAX_ITERATIONS = 15;

/** Default campaign data directory, relative to the attack-lab workspace. */
export const DEFAULT_CAMPAIGN_DIR = 'data/campaigns';
