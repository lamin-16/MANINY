import { Finding } from "./types.js";

export type AgentProviderId = "openai" | "claude" | "deepseek" | "gemini" | "custom";

export interface AgentConfig {
  provider: AgentProviderId;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface AgentInsight {
  provider: AgentProviderId;
  model: string;
  findingId?: string;
  ruleId?: string;
  role: "triage" | "remediation-advice" | "defensive-review";
  summary: string;
  confidence: "low" | "medium" | "high";
  generatedAt: string;
}

export function discoverConfiguredAgents(requestedProviders?: AgentProviderId[]): AgentConfig[] {
  const catalog: Array<{
    provider: AgentProviderId;
    envKey: string;
    defaultModel: string;
    modelEnv?: string;
    defaultBaseUrl?: string;
    baseUrlEnv?: string;
  }> = [
    {
      provider: "openai",
      envKey: "OPENAI_API_KEY",
      defaultModel: "gpt-6.2-sol",
      modelEnv: "OPENAI_MODEL",
      defaultBaseUrl: "https://api.openai.com/v1",
      baseUrlEnv: "OPENAI_BASE_URL",
    },
    {
      provider: "claude",
      envKey: "ANTHROPIC_API_KEY",
      defaultModel: "claude-sonnet-5-5",
      modelEnv: "ANTHROPIC_MODEL",
      defaultBaseUrl: "https://api.anthropic.com/v1",
      baseUrlEnv: "ANTHROPIC_BASE_URL",
    },
    {
      provider: "deepseek",
      envKey: "DEEPSEEK_API_KEY",
      defaultModel: "deepseek-flash",
      modelEnv: "DEEPSEEK_MODEL",
      defaultBaseUrl: "https://api.deepseek.com",
      baseUrlEnv: "DEEPSEEK_BASE_URL",
    },
    {
      provider: "gemini",
      envKey: "GEMINI_API_KEY",
      defaultModel: "gemini-2.5-flash",
      modelEnv: "GEMINI_MODEL",
      defaultBaseUrl: "https://generativelanguage.googleapis.com/v1beta",
      baseUrlEnv: "GEMINI_BASE_URL",
    },
    {
      provider: "custom",
      envKey: "CUSTOM_LLM_API_KEY",
      defaultModel: "custom-model",
      modelEnv: "CUSTOM_LLM_MODEL",
      baseUrlEnv: "CUSTOM_LLM_BASE_URL",
    },
  ];

  const filtered =
    requestedProviders && requestedProviders.length > 0
      ? catalog.filter((item) => requestedProviders.includes(item.provider))
      : catalog;

  const active: AgentConfig[] = [];

  for (const item of filtered) {
    const apiKey = process.env[item.envKey]?.trim();
    const baseUrl = item.baseUrlEnv ? process.env[item.baseUrlEnv]?.trim() || item.defaultBaseUrl : item.defaultBaseUrl;
    const model = item.modelEnv ? process.env[item.modelEnv]?.trim() || item.defaultModel : item.defaultModel;

    if (apiKey && (item.provider !== "custom" || baseUrl)) {
      active.push({
        provider: item.provider,
        model,
        apiKey,
        ...(baseUrl ? { baseUrl } : {}),
      });
    }
  }

  return active;
}

async function queryOpenAiCompatible(
  baseUrl: string,
  apiKey: string,
  model: string,
  prompt: string
): Promise<string | null> {
  const endpoint = `${baseUrl.replace(/\/+$/, "")}/chat/completions`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content:
            "You are a concise defensive application security agent inside MANINY. Give practical remediation guidance without unsafe payloads.",
        },
        { role: "user", content: prompt },
      ],
    }),
  });

  if (!res.ok) return null;
  const data = (await res.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  return data.choices?.[0]?.message?.content?.trim() || null;
}

async function queryClaude(cfg: AgentConfig, prompt: string): Promise<string | null> {
  const baseUrl = (cfg.baseUrl || "https://api.anthropic.com/v1").replace(/\/+$/, "");
  const res = await fetch(`${baseUrl}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": cfg.apiKey || "",
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: cfg.model,
      max_tokens: 300,
      system:
        "You are a defensive security code reviewer inside MANINY. Provide concise, safe remediation advice.",
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) return null;
  const data = (await res.json()) as {
    content?: Array<{ type?: string; text?: string }>;
  };
  return data.content?.find((b) => b.type === "text")?.text?.trim() || null;
}

async function queryGemini(cfg: AgentConfig, prompt: string): Promise<string | null> {
  const baseUrl = (cfg.baseUrl || "https://generativelanguage.googleapis.com/v1beta").replace(
    /\/+$/,
    ""
  );
  const url = `${baseUrl}/models/${encodeURIComponent(cfg.model)}:generateContent?key=${encodeURIComponent(cfg.apiKey || "")}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
    }),
  });

  if (!res.ok) return null;
  const data = (await res.json()) as {
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  };
  return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || null;
}

export async function runMultiAgentAdvisory(
  agents: AgentConfig[],
  findings: Finding[]
): Promise<AgentInsight[]> {
  if (agents.length === 0 || findings.length === 0) {
    return [];
  }

  const topFindings = findings.slice(0, 5);
  const prompt = [
    "Review these MANINY security findings and provide brief defensive fix recommendations:",
    ...topFindings.map(
      (f, i) =>
        `${i + 1}. [${f.ruleId}] (${f.severity}) status=${f.status} loc=${f.filePath || f.targetUrl || "unknown"}:${f.line || ""} - ${f.title}`
    ),
  ].join("\n");

  const insights: AgentInsight[] = [];

  for (const agent of agents) {
    try {
      let text: string | null = null;
      if (agent.provider === "openai" || agent.provider === "deepseek" || agent.provider === "custom") {
        text = await queryOpenAiCompatible(
          agent.baseUrl || "https://api.openai.com/v1",
          agent.apiKey || "",
          agent.model,
          prompt
        );
      } else if (agent.provider === "claude") {
        text = await queryClaude(agent, prompt);
      } else if (agent.provider === "gemini") {
        text = await queryGemini(agent, prompt);
      }

      if (text) {
        insights.push({
          provider: agent.provider,
          model: agent.model,
          role:
            agent.provider === "claude"
              ? "remediation-advice"
              : agent.provider === "gemini"
                ? "defensive-review"
                : "triage",
          summary: text,
          confidence: "high",
          generatedAt: new Date().toISOString(),
        });
      }
    } catch {
      // Keep MANINY non-blocking if an external AI provider times out or is unreachable
    }
  }

  return insights;
}
