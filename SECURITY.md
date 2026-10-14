# Security policy

## Reporting a vulnerability

Please email **jason@digitalarchon.com.au** with the details and, if you can, steps to
reproduce. Don't open a public issue or pull request for a vulnerability.

You'll get a reply as soon as I can manage. This is a one-person project with no bug bounty,
but reports are taken seriously and credited in the fix unless you'd rather not be named.

A report made in the app (**Export…** with **Redact** ticked) helps, and leaves out names, hosts,
addresses and paths under your home folder. Read it before you send it all the same.

## Supported versions

DA Privacy Kit is in beta. Only the latest release (or `main`) gets fixes.

## What's in scope

Anything that breaks one of DA Privacy Kit's promises, for example:

- the administrator helper doing more than its named actions: writing content the app sent it,
  touching a file, unit, sysctl or policy that isn't on its lists, being led through a link to
  somewhere else, or being used by another account or program;
- a scan that changes something, or that contacts the network;
- an online test, or the browser download, contacting a host it didn't list first, following a
  redirect elsewhere, or sending more about the computer than it says;
- a fix that changes something its dry run didn't show, that can't be reverted from History when
  it says it can, or a revert that overwrites or removes something that isn't the fix's;
- secrets, file contents, account names or file names reaching a report, the undo log, a
  notification, the terminal's error output or a crash dump, or surviving redaction in an export;
- another program, another account or a web page reaching the app's local server: a way round
  its one-time token, its session cookie or its Host check;
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
