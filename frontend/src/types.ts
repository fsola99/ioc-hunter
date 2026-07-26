export type Verdict = "malicious" | "suspicious" | "harmless" | "unknown";

export type IoCType =
  | "md5"
  | "sha1"
  | "sha256"
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url";

export interface EngineStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
}

export interface VendorVerdict {
  engine: string;
  category: string;
  result: string | null;
  version: string | null;
  updated: string | null;
}

export interface Mitigation {
  id: string;
  name: string;
}

export interface Technique {
  id: string;
  name: string;
  description: string | null;
  link: string | null;
  severities: string[];
  signatures: string[];
  mitigations: Mitigation[];
}

export interface Tactic {
  id: string;
  name: string;
  link: string | null;
  techniques: Technique[];
}

export interface SandboxMitre {
  sandbox: string;
  tactics: Tactic[];
}

export interface AbuseIpdbSummary {
  confidence_score: number;
  total_reports: number;
  distinct_reporters: number;
  country_code: string | null;
  isp: string | null;
  usage_type: string | null;
  is_tor: boolean;
  last_reported_at: string | null;
}

export interface FileDetail {
  kind: "file";
  md5: string | null;
  sha1: string | null;
  sha256: string | null;
  size: number | null;
  type_description: string | null;
  magic: string | null;
  names: string[];
  threat_label: string | null;
  threat_categories: string[];
  signer: string | null;
  signature_valid: boolean | null;
}

export interface IpDetail {
  kind: "ip";
  asn: number | null;
  as_owner: string | null;
  country: string | null;
  continent: string | null;
  network: string | null;
  registry: string | null;
  jarm: string | null;
  abuseipdb: AbuseIpdbSummary | null;
}

export interface DnsRecord {
  type: string;
  value: string;
  ttl: number | null;
}

export interface DomainDetail {
  kind: "domain";
  registrar: string | null;
  created_at: string | null;
  updated_at: string | null;
  expires_at: string | null;
  categories: Record<string, string>;
  dns_records: DnsRecord[];
  popularity_ranks: Record<string, number>;
}

export interface UrlDetail {
  kind: "url";
  final_url: string | null;
  title: string | null;
  response_code: number | null;
  content_type: string | null;
  categories: Record<string, string>;
  outgoing_links: string[];
}

export type Detail = FileDetail | IpDetail | DomainDetail | UrlDetail;

export interface Report {
  indicator: string;
  raw_input: string;
  ioc_type: IoCType;
  verdict: Verdict;
  stats: EngineStats;
  detection_ratio: string;
  reputation: number;
  community_votes_harmless: number;
  community_votes_malicious: number;
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
  last_analysed: string | null;
  vendors: VendorVerdict[];
  detail: Detail;
  source_link: string;
  retrieved_at: string;
  cached: boolean;
}

export interface DnsLookup {
  hostname: string;
  resolved_ips: string[];
}

export interface BehaviourReport {
  processes_created: string[];
  services_started: string[];
  mutexes_created: string[];
  files_opened: string[];
  files_written: string[];
  registry_keys_opened: string[];
  modules_loaded: string[];
  processes_terminated: string[];
  dns_lookups: DnsLookup[];
  mitre: SandboxMitre[];
  cached: boolean;
}

export interface RelatedIndicator {
  indicator: string;
  ioc_type: IoCType;
  verdict: Verdict;
  detections: number;
  total_engines: number;
  detail: string | null;
  observed_at: string | null;
}

export interface RelationsReport {
  relation: string;
  items: RelatedIndicator[];
  truncated: boolean;
  cached: boolean;
}

export interface AttackTechnique {
  id: string;
  name: string;
  description: string;
  platforms: string[];
  tactics: string[];
  is_subtechnique: boolean;
  parent: string | null;
  url: string | null;
  mitigations: Mitigation[];
}

export interface AttackTechniqueSummary {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  mitigation_count: number;
  subtechnique_count: number;
}

export interface AttackTactic {
  id: string;
  name: string;
  shortname: string;
  description: string;
  url: string | null;
  techniques: AttackTechniqueSummary[];
}

export interface AttackMatrix {
  version: string;
  technique_count: number;
  platforms: string[];
  tactics: AttackTactic[];
}

export interface AttackTechniqueDetail {
  technique: AttackTechnique;
  tactic_names: Record<string, string>;
  subtechniques: AttackTechnique[];
  parent: AttackTechnique | null;
}

export interface ClassificationResult {
  raw_input: string;
  indicator: string;
  ioc_type: IoCType;
  family: string;
}

export interface ProviderStatus {
  name: string;
  configured: boolean;
  detail: string;
}

export interface ServiceStatus {
  status: string;
  version: string;
  providers: ProviderStatus[];
}
