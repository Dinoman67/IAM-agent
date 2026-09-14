import { Container, getContainer } from "@cloudflare/containers";

export class IAMAgentContainer extends Container {
  defaultPort = 7860;
  sleepAfter = "15m";
  envVars = {
    PORT: "7860",
    STATE_STORE: "memory",
    MOCK_LLM: "true",
    RATE_LIMIT_PER_MIN: "30",
    ALLOWED_ORIGINS: "*",
  };

  override onStart() {
    console.log("IAM Agent container started");
  }

  override onStop() {
    console.log("IAM Agent container stopped");
  }

  override onError(error: unknown) {
    console.error("IAM Agent container error:", error);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return getContainer(env.IAM_AGENT).fetch(request);
  },
} satisfies ExportedHandler<Env>;
