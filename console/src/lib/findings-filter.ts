import { validateSchema } from "@/lib/protocol/validate";

/** Filter of the findings view (`/findings?agent=&target=&classifier=&fp=1`). */
export interface FindingFilter {
  agentId?: string;
  targetId?: string;
  classifier?: string;
  includeFalsePositives?: boolean;
}

export type SearchParams = Record<string, string | string[] | undefined>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : undefined);

/** Query string -> filter; values that do not match the contract formats are ignored. */
export function parseFindingFilter(sp: SearchParams): FindingFilter {
  const agent = one(sp.agent);
  const target = one(sp.target);
  const classifier = one(sp.classifier);
  return {
    agentId: agent && UUID.test(agent) ? agent : undefined,
    targetId: target && validateSchema("TargetId", target).ok ? target : undefined,
    classifier: classifier && validateSchema("ClassifierId", classifier).ok ? classifier : undefined,
    includeFalsePositives: one(sp.fp) === "1",
  };
}
