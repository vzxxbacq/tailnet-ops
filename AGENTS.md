# Working rules

- tailnet-ops is a reusable tool, and this repository must stay publishable. Never commit site data:
  - real addresses or a real site's host names;
  - inventories, keys, auth keys or tokens;
  - links to private documents.

  Examples and tests use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and placeholder names.
- Site data lives in the site directory: `~/.config/tailnet-ops/` by default, or `--site DIR` or `TN_SITE`. Read it at run time. Never copy it into the repository, test fixtures, commit messages or printed examples.
- Every command plans first and changes nothing by default. Touch a server only after the owner has explicitly approved that specific change. Before running it, state what will change and how to roll it back.
- Leave existing services on every host alone. Only add new services, on ports that are free.
- Use Python 3 with the standard library only. Run `make check` before every commit; it covers the tests plus a guard over tracked files and all history. Set `PYTHONDONTWRITEBYTECODE=1`. Tests use fake fixtures and never contact a real host.
- Report to the owner in short Chinese. Prefer a table or a diagram to long text. Stop at each milestone the owner can test by hand.
