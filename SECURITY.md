# Security policy

## Reporting a vulnerability
**Do not open a public issue.** Use GitHub private reporting: **Security** tab → **Report a vulnerability**.

Please include: the affected version or commit, the component (console / agent / connector), reproduction steps and the estimated impact.

## Commitment
- Acknowledgment within 72 h
- Initial assessment within 7 days
- Fix and security advisory coordinated with the person who reported the issue

## Supported versions
The project is pre-alpha: only the `main` branch receives fixes.

## Particularly sensitive scope
- Any leak of a raw sensitive value outside the agent
- Any way for the console, or a third party, to initiate a connection to an agent
- Bypassing agent or console authentication
- Agent privilege escalation on the monitored databases
