#!/usr/bin/env python3
"""
Standalone script to authenticate to Monarch Money for headless environments
where the MCP server's automatic browser login page isn't reachable.

Monarch blocks programmatic password/MFA login behind a Cloudflare CAPTCHA,
so this script accepts a browser session cookie instead of a password.
"""

import asyncio
import sys
from pathlib import Path

# Add the src directory to the Python path for imports
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from monarchmoney import MonarchMoney, LoginFailedException
from dotenv import load_dotenv

from monarch_mcp.secure_session import secure_session


async def main():
    load_dotenv()

    print("\n🏦 Monarch Money - Headless Setup")
    print("=" * 45)
    print("1. Sign in at app.monarch.com in a normal browser")
    print("2. Open DevTools -> Network tab, click any 'graphql' request")
    print("3. Under Request Headers, copy the full Cookie value")
    print("4. Paste it below\n")

    cookie_string = input("Cookie header: ").strip()
    if not cookie_string:
        print("❌ No cookie provided. Aborting.")
        return

    secure_session.delete_token()
    print("🗑️ Cleared existing secure sessions")

    mm = MonarchMoney()
    try:
        print("\nVerifying cookie against Monarch...")
        await mm.login_with_cookies(cookie_string, save_session=False)
        accounts = await mm.get_accounts()
        account_count = len(accounts.get("accounts", [])) if accounts else 0
        print(f"✅ Found {account_count} accounts")

        secure_session.save_authenticated_session(mm)
        print("✅ Session saved securely to keyring!")

        print("\n🎉 Setup complete! You can now use these tools in Claude Desktop:")
        print("   • get_accounts - View all your accounts")
        print("   • get_transactions - Recent transactions")
        print("   • get_budgets - Budget information")
        print("   • get_cashflow - Income/expense analysis")
        print("\n💡 Session will persist across Claude restarts (weeks/months).")
        print("   Repeat this script with a fresh cookie once it expires.")

    except LoginFailedException as e:
        print(f"\n❌ Cookie login failed: {e}")
        print("Copy a fresh Cookie header from an active app.monarch.com tab and retry.")
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"\n❌ Login failed: {e}")
        print(f"Error type: {type(e)}")


if __name__ == "__main__":
    asyncio.run(main())
