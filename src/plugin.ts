import { 
  type Action, 
  type Plugin,
  type IAgentRuntime,
  type Memory,
  type State,
  elizaLogger 
} from "@elizaos/core";
import type { Transaction, PublicKey } from "@solana/web3.js";

export class BentoSecurityPlugin implements Plugin {
    private guardians: PublicKey[];
    private maxRiskScore: number;
    private approvalThreshold: number;
    private cooldownPeriod: number;

    constructor(config: {
        guardians: string[];
        maxRiskScore?: number;
        approvalThreshold?: number;
        cooldownPeriod?: number;
    }) {
        this.guardians = config.guardians.map((g) => new PublicKey(g));
        this.maxRiskScore = config.maxRiskScore || 0.7;
        this.approvalThreshold = config.approvalThreshold || 2;
        this.cooldownPeriod = config.cooldownPeriod || 3600; // 1 hour
    }

    name = "BENTO Security Layer";
    description = "Security guardrails for AI agent transactions";

    async validateTransaction(runtime: IAgentRuntime, tx: Transaction): Promise<boolean> {
        const riskScore = await this.calculateRiskScore(tx, runtime);
        
        if (riskScore > this.maxRiskScore) {
            elizaLogger.warn(`Transaction risk score ${riskScore} exceeds max ${this.maxRiskScore}`);
            return false;
        }

        if (!await this.checkCooldown(runtime)) {
            elizaLogger.warn("Cooldown period active for transaction");
            return false;
        }

        return true;
    }

    async getRequiredApprovals(tx: Transaction): Promise<string[]> {
        const riskScore = await this.calculateRiskScore(tx);
        
        if (riskScore > 0.8) return this.guardians.map(g => g.toBase58());
        if (riskScore > 0.5) return this.guardians.slice(0, 2).map(g => g.toBase58());
        return this.guardians.slice(0, 1).map(g => g.toBase58());
    }

    private async calculateRiskScore(tx: Transaction, runtime?: IAgentRuntime): Promise<number> {
        let score = 0;
        
        // Check for blind signing
        if (this.hasBlindSigning(tx)) score += 0.4;
        
        // Check for large transfers
        if (await this.isLargeTransfer(tx, runtime)) score += 0.3;
        
        // Check for unknown programs
        if (this.hasUnknownPrograms(tx)) score += 0.2;
        
        // Check for swap operations
        if (this.hasSwapOperations(tx)) score += 0.2;
        
        return Math.min(score, 1.0);
    }

    private hasBlindSigning(tx: Transaction): boolean {
        return tx.instructions.some(ix => 
            ix.programId.toBase58() === "11111111111111111111111111111111"
        );
    }

    private async isLargeTransfer(tx: Transaction, runtime?: IAgentRuntime): Promise<boolean> {
        if (!runtime) return false;
        
        const transferAmounts = tx.instructions
            .filter(ix => ix.programId.toBase58() === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .map(ix => {
                const raw = ix.data;
                return raw.length >= 8 ? Number(raw.readBigUint64LE(0)) : 0;
            });
        
        const maxAmount = Math.max(...transferAmounts);
        const threshold = 1000 * Math.pow(10, 6); // 1000 USDC
        
        return maxAmount > threshold;
    }

    private hasUnknownPrograms(tx: Transaction): boolean {
        const knownPrograms = new Set([
            "11111111111111111111111111111111", // System
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // Token
            "JUP6Lkj7prxfcoo2ZY2c9AWpAsCJddP8j9bh8v9kQvNQ", // Jupiter
            "MFvXLqotB2tG7z4WmrYUJ4F5J5J5J5J5J5J5J5J5J5J", // Marginfi
        ]);
        
        return tx.instructions.some(ix => !knownPrograms.has(ix.programId.toBase58()));
    }

    private hasSwapOperations(tx: Transaction): boolean {
        return tx.instructions.some(ix => 
            ix.programId.toBase58() === "JUP6Lkj7prxfcoo2ZY2c9AWpAsCJddP8j9bh8v9kQvNQ"
        );
    }

    private async checkCooldown(runtime: IAgentRuntime): Promise<boolean> {
        const lastTx = await runtime.getMemory("last_bento_transaction");
        
        if (!lastTx) return true;
        
        const elapsed = Date.now() - (lastTx.createdAt?.getTime() || 0);
        return elapsed > this.cooldownPeriod * 1000;
    }
}