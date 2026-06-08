use anchor_lang::prelude::*;

declare_id!("bNTAxj9fpGwyXj9fpGwyXj9fpGwyXj9fpGwyXj9fpGwyX");

#[program]
pub mod bento_agent_security {
    use super::*;

    /// Initialize BENTO security configuration for an agent vault
    pub fn initialize_security(
        ctx: Context<InitializeSecurity>,
        max_risk_score: f32,
        approval_threshold: u8,
    ) -> Result<()> {
        let security = &mut ctx.accounts.security_config;
        security.owner = ctx.accounts.owner.key();
        security.max_risk_score = max_risk_score.max(0.0).min(1.0);
        security.approval_threshold = approval_threshold;
        security.cooldown_seconds = 3600;
        security.last_transaction = 0;
        security.bump = *ctx.bumps.get("security_config").unwrap();
        Ok(())
    }

    /// Record a transaction approval event
    pub fn record_approval(ctx: Context<RecordApproval>, risk_score: f32) -> Result<()> {
        let security = &mut ctx.accounts.security_config;
        
        require!(
            risk_score <= security.max_risk_score,
            BentoError::RiskScoreExceeded
        );

        security.last_transaction = Clock::get()?.unix_timestamp;
        
        emit!(TransactionApproved {
            vault: ctx.accounts.owner.key(),
            risk_score,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Guardian approves a transaction
    pub fn guardian_approve(ctx: Context<GuardianApprove>) -> Result<()> {
        let security = &mut ctx.accounts.security_config;
        let guardian = ctx.accounts.guardian.key();

        if !security.guardians.contains(&guardian) {
            security.guardians.push(guardian);
        }

        Ok(())
    }

    /// Check cooldown period
    pub fn check_cooldown(ctx: Context<CheckCooldown>) -> Result<bool> {
        let security = &ctx.accounts.security_config;
        let elapsed = Clock::get()?.unix_timestamp - security.last_transaction;
        
        Ok(elapsed >= security.cooldown_seconds)
    }
}

#[account]
pub struct SecurityConfig {
    pub owner: Pubkey,
    pub max_risk_score: f32,
    pub approval_threshold: u8,
    pub cooldown_seconds: i64,
    pub last_transaction: i64,
    pub guardians: Vec<Pubkey>,
    pub bump: u8,
}

#[event]
pub struct TransactionApproved {
    pub vault: Pubkey,
    pub risk_score: f32,
    pub timestamp: i64,
}

#[error_code]
pub enum BentoError {
    #[msg("Risk score exceeds maximum allowed")]
    RiskScoreExceeded,
    #[msg("Cooldown period not elapsed")]
    CooldownActive,
    #[msg("Insufficient guardian approvals")]
    InsufficientApprovals,
}

#[derive(Accounts)]
pub struct InitializeSecurity<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 4 + 1 + 8 + 8 + 4 + 32 + 1,
        seeds = [b"security", owner.key().as_ref()],
        bump
    )]
    pub security_config: Account<'info, SecurityConfig>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RecordApproval<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    
    #[account(
        mut,
        seeds = [b"security", owner.key().as_ref()],
        bump = security_config.bump
    )]
    pub security_config: Account<'info, SecurityConfig>,
}

#[derive(Accounts)]
pub struct GuardianApprove<'info> {
    #[account(mut)]
    pub guardian: Signer<'info>,
    
    #[account(mut)]
    pub owner: AccountInfo<'info>,
    
    #[account(
        mut,
        seeds = [b"security", owner.key().as_ref()],
        bump = security_config.bump
    )]
    pub security_config: Account<'info, SecurityConfig>,
}

#[derive(Accounts)]
pub struct CheckCooldown<'info> {
    pub owner: Signer<'info>,
    
    #[account(
        seeds = [b"security", owner.key().as_ref()],
        bump = security_config.bump
    )]
    pub security_config: Account<'info, SecurityConfig>,
}