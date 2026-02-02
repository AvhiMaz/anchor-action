use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // Vulnerable: invoke_signed without bump validation
        let seeds = &[b"vault".as_ref()];
        let signer_seeds = &[&seeds[..]];
        invoke_signed(
            &system_instruction::transfer(
                ctx.accounts.vault.key,
                ctx.accounts.recipient.key,
                amount,
            ),
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.recipient.to_account_info(),
            ],
            signer_seeds,
        )?;

        Ok(())
    }

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // Vulnerable: PDA derived without verifying program ID
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"config"],
            ctx.accounts.other_program.key,
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Vulnerable: raw AccountInfo without CHECK comment
    pub vault: AccountInfo<'info>,
    pub recipient: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    // Vulnerable: #[account] without constraints
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account()]
    pub other_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub value: u64,
}
