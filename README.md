# ElizaOS BENTO Security Plugin

An ElizaOS plugin for BENTO transaction security integration with AI agent validation.

## Features
- Risk-based transaction approval for AI agents
- Guardian signature requirements
- Cooldown period enforcement
- Policy-based transaction validation

## Installation

```bash
npx elizaos plugins install @elizaos/plugin-bento
```

## Usage

```typescript
import { BentoSecurityPlugin } from "@elizaos/plugin-bento";

const plugin = new BentoSecurityPlugin({
  guardians: ["Guardian1PublicKey", "Guardian2PublicKey"],
  maxRiskScore: 0.7,
  approvalThreshold: 2,
});

agent.use(plugin);
```