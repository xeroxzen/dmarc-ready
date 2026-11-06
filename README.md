# dmarc-ready

**Is your domain ready for DMARC `p=reject`?**

Moving a domain from `p=none` to `p=reject` stops forged mail, but it also rejects your own mail from any service you forgot to configure. dmarc-ready reads the DMARC aggregate reports your domain already receives and lists every sender that would lose mail if you enforced today, with the domain each one authenticates as, so you know what to fix first.

```console
$ dmarc-ready --resolve reports/
example.com: NOT READY: these senders would lose mail under p=reject.
  Policy now: p=none. 42 reports covering 14.0 days. 18204 messages, 96.8% pass DMARC.
  Unaligned (1): Authenticates, but as a different domain. Legitimate services look like this; set up DKIM or a return-path for this domain before enforcing.
    198.51.100.7 (o1.mailgun.example)  540 msgs, 0% pass  authenticates as: mailgun.org
  Unauthenticated (3): Passes neither SPF nor DKIM for any domain. Usually forged mail or forwarding; p=reject is meant to block this.
    203.0.113.9  31 msgs, 0% pass
    ...
  Aligned (6): Passes DMARC. Safe under p=reject.
    192.0.2.1 (mail-eopbgr.outbound.protection.example)  17401 msgs, 100% pass
    ...
```

It reads the `.xml`, `.xml.gz` and `.zip` files that receivers send, as they arrive. Nothing leaves your machine unless you pass `--resolve`, which looks up reverse-DNS names for sender IPs.

## Install

```bash
uv tool install git+https://github.com/xeroxzen/dmarc-ready
```

Requires Python 3.10 or later.

## Get started

1. Make sure your domain's DMARC record has a `rua=` address, for example `v=DMARC1; p=none; rua=mailto:dmarc@example.com`.
2. Collect at least 7 days of the reports that arrive at that address. Save the attachments to one folder without unzipping them.
3. Run:

   ```bash
   dmarc-ready --resolve path/to/reports/
   ```

4. Fix each sender under **Unaligned** and **Partly aligned**, collect another week of reports, and run it again.
5. When the verdict is `READY`, move to `p=quarantine`, check the reports again, then move to `p=reject`.

## How senders are classified

Each sending IP address is put in one of four groups, based on what receivers reported over the whole period.

| Group | What it means | What to do |
|---|---|---|
| Aligned | Every message passed DMARC. | Nothing. |
| Partly aligned | Some messages passed and some didn't. Often a server that signs only some mail, or a shared IP used by two services. | Find the mail that fails and configure it. Blocks enforcement. |
| Unaligned | Messages passed SPF or DKIM, but for a different domain, such as the sending platform's own. This is what a legitimate marketing, ticketing or invoicing service looks like before it is set up for your domain. | Set up DKIM signing for your domain in that service, or a custom return-path. Blocks enforcement. |
| Unauthenticated | Messages passed neither SPF nor DKIM for any domain. Usually forged mail. Sometimes forwarded mail, which DMARC has always handled imperfectly. | Nothing, if you don't recognise the sender. This is what `p=reject` exists to stop. |

The verdict is `READY` when no sender is unaligned or partly aligned, and the reports cover at least 7 days. With less data, it says `NOT ENOUGH DATA`: a monthly payroll run or a quarterly newsletter can hide in a short window, so consider waiting a full month before enforcing.

## Command-line reference

```
dmarc-ready [--json] [--resolve] PATH [PATH ...]
```

| Option | Effect |
|---|---|
| `PATH` | A report file, or a folder of them. Folders are read one level deep. |
| `--json` | Print one JSON object per domain, with every sender, instead of the summary. |
| `--resolve` | Look up reverse-DNS names for up to 200 sender IPs. |

Exit status: `0` when every domain is ready, `1` when any domain is not ready or has too little data, and `2` when any file couldn't be read. Status 2 takes priority, so a script never mistakes a partly read set of reports for a clean result.

## Handling untrusted reports

Anyone can send a file to your `rua=` address, so dmarc-ready treats every report as hostile:

- XML is parsed with [defusedxml](https://github.com/tiran/defusedxml), with DTDs forbidden, so entity-expansion and external-entity attacks fail.
- Files are capped at 20 MB, decompressed reports at 50 MB, zip files at 10 members, and reports at 100,000 records. Sizes are measured while reading, not taken from headers.
- A file that fails any check is skipped with a message, and the exit status is `2`.

## What it doesn't do

- It doesn't fetch reports from a mailbox. Save the attachments first.
- It doesn't read forensic (`ruf=`) reports.
- It can't tell a forwarded message from a forged one. Both appear as unauthenticated.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/xeroxzen/dmarc-ready/blob/main/CONTRIBUTING.md) and [SECURITY.md](https://github.com/xeroxzen/dmarc-ready/blob/main/SECURITY.md). The [changelog](https://github.com/xeroxzen/dmarc-ready/blob/main/CHANGELOG.md) lists every release.

## License

[MIT](https://github.com/xeroxzen/dmarc-ready/blob/main/LICENSE)
