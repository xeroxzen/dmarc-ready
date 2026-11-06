# Security policy

## Reporting a vulnerability in dmarc-ready

dmarc-ready reads files from senders you don't control, so parser weaknesses matter. Examples: a report that bypasses the size limits, triggers entity expansion, crashes the tool instead of being skipped, or makes a failing sender appear aligned. Report it privately:

- Use [GitHub private vulnerability reporting](https://github.com/xeroxzen/dmarc-ready/security/advisories/new), or
- Email andilembele020@gmail.com with the subject `dmarc-ready security`.

Include the version and, if you can, a minimal report file that reproduces the problem. Don't send real reports: they contain other organisations' IP addresses and volumes. You'll get an acknowledgement within 3 working days.

## Supported versions

Only the latest release receives fixes.
