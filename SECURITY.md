# Security policy

## Reporting a vulnerability

Don't open a public issue or pull request for a vulnerability. Report it privately, with the details and, if you
can, steps to reproduce, in one of two ways:

- **GitHub's private vulnerability reporting**: *Report a vulnerability* on the repository's
  [Security tab](https://github.com/DigitalArchon/DAPrivacyKit/security). The report travels over HTTPS and is
  seen only by the maintainer (and you), not stored in anyone's mailbox; this is the way to send something you
  wouldn't put in a plain email.
- **Email** to **jason@digitalarchon.com.au**. Email is usually not encrypted end to end: keep exploit details
  for the private report above, or ask by email for an encrypted channel first.

What to expect from a one-person project with no bug bounty:

- an acknowledgement within **7 days**, and an assessment (is it a vulnerability, how serious) within **14**;
- a fix released within **90 days** of the report, sooner for anything that runs as administrator or leaks what a
  user expects to stay on the computer; if a fix will take longer, you're told why and when;
- the vulnerability is published, with a GitHub security advisory and a note in the release, once the fix is out,
  or at 90 days, whichever comes first, unless we agree otherwise; you're credited unless you'd rather not be named.

A report made in the app (**Export…** with **Redact** ticked) helps, and leaves out names, hosts,
addresses and paths under your home folder. Read it before you send it all the same.

Releases are signed: how to check one, and what the release key is, is in the README (*Verifying a download*) and
[packaging/README.md](packaging/README.md).

## Supported versions

DA Privacy Kit is in beta. Only the latest release (or `main`) gets fixes.

## What's in scope

Anything that breaks one of DA Privacy Kit's promises, for example:

- the administrator helper doing more than its named actions: writing content the app sent it,
  touching a file, unit, sysctl or policy that isn't on its lists, being led through a link to
  somewhere else, or being used by another account or program;
- a scan that changes something, or that contacts the network;
- an online test, the browser download or Check for updates… contacting a host it didn't list first, following a
  redirect elsewhere, or sending more about the computer than it says;
- Check for updates… putting in place a file the release key the copy carries didn't verify, an older version or
  the same one, or replacing or removing anything but the AppImage it runs from and the old copy it kept;
- a fix that changes something its dry run didn't show, that can't be reverted from History when
  it says it can, or a revert that overwrites or removes something that isn't the fix's;
- secrets, file contents, account names or file names reaching a report, the undo log, a
  notification, the terminal's error output or a crash dump, or surviving redaction in an export;
- another program, another account or a web page reaching the app's local server: a way round
  its one-time launch token, its session token (the X-Token header every API call carries) or its Host check;
- Verify a download calling a file verified that isn't: a signature check or a pinned key
  fingerprint bypassed;
- a way out of the sandbox Tor Browser, Mullvad Browser or View offline… run in: to your files,
  to this computer's services or your home network, to tor's control port past its filter, or a
  browser archive other than the verified one being unpacked or started;
- a tool changing the file it was given, or keeping something after it said it keeps nothing;
- a crafted file (an archive, a package, a document, a key, a checksum list) making the app do
  more than read it.

Weaknesses in upstream projects (mat2, ExifTool, bubblewrap, passt, GnuPG, Tor Browser, Mullvad
Browser, OpenSnitch, WebKitGTK and so on) should go to those projects, though a heads-up is
welcome if DA Privacy Kit can mitigate them.

## Bugs that aren't vulnerabilities

A check that is wrong about your computer, a fix that doesn't do what it says, or anything else
that isn't a security hole: open an issue at
<https://github.com/DigitalArchon/DAPrivacyKit/issues>. Attach a redacted report if it helps,
never an unredacted one: an issue is public.
