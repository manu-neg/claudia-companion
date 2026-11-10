# Vendored fonts

**TL;DR:** Four OFL-1.1 families, latin subset, copied byte-for-byte from the pinned `@fontsource` npm packages (jsDelivr `/npm/`). Loaded by `static/fonts.css` from `/static/fonts/` only (CSP `font-src 'self'`, C6); never from a CDN at run time. Font files are exempt from the file-header rule.

| Family | Role | Package | Licence |
|---|---|---|---|
| Pixelify Sans 400, 700 | window chrome, menus, buttons (`--font-chrome`) | `@fontsource/pixelify-sans@5.3.0` | `OFL-pixelify-sans.txt` |
| Public Sans 400, 600 | list and body text (`--font-body`) | `@fontsource/public-sans@5.3.0` | `OFL-public-sans.txt` |
| Catamaran 400, 700, 800 | Aero OS: chrome and body (`--font-chrome`, `--font-body` under `data-os="aero"`) | `@fontsource/catamaran@5.2.8` | `OFL-catamaran.txt` |
| Nunito 400, 600, 800 | Neumorph OS: chrome and body (`--font-chrome`, `--font-body` under `data-os="neumorph"`) | `@fontsource/nunito@5.3.0` | `OFL-nunito.txt` |

## Files

| File | Taken from (package) | sha256 |
|---|---|---|
| `pixelify-sans-400.woff2` | `files/pixelify-sans-latin-400-normal.woff2` | `d830612ac9131788ebae754b9268f83f7c1d3ffa9bc0f9a5514207a8283fe71e` |
| `pixelify-sans-700.woff2` | `files/pixelify-sans-latin-700-normal.woff2` | `c836cfa5c0e9d62ea9b890e0418d52a6004149090a521cd198a8c09f5d5ab893` |
| `public-sans-400.woff2` | `files/public-sans-latin-400-normal.woff2` | `36274b5787b4f03b27e65ae971d6c808a96838ccd60c9dabaee154889b6bba82` |
| `public-sans-600.woff2` | `files/public-sans-latin-600-normal.woff2` | `c7842f97346df1b3b470e9d71acde90f132dd858508ec5ae6606401e5d0938f7` |
| `catamaran-400.woff2` | `files/catamaran-latin-400-normal.woff2` | `688ccbf5bc56133acbea6b9f57ba0e1e7506eae9fb095ca433cbf036c0ce1740` |
| `catamaran-700.woff2` | `files/catamaran-latin-700-normal.woff2` | `afd96404e6bbda8d5473240c6dde391ad7a6f0e12739b5d20d31b60f61b22efa` |
| `catamaran-800.woff2` | `files/catamaran-latin-800-normal.woff2` | `68df2c2f303e1f5d5ab497db1416e32caffd9a8bf50531d7cf4fed37f04f7881` |
| `nunito-400.woff2` | `files/nunito-latin-400-normal.woff2` | `a5906e15ceb68f73d3b2c2076b4057c3f6ed401186d56283b45ce12944ca0735` |
| `nunito-600.woff2` | `files/nunito-latin-600-normal.woff2` | `45f437de32ff5973eb5616b43c1308bf9fe897442f3d78a603c4cd0a06d66573` |
| `nunito-800.woff2` | `files/nunito-latin-800-normal.woff2` | `2363d3ed037283ebb961e8c4b4917e40a8bc8853cf9965cf1ea7b4daa1df630a` |
| `OFL-pixelify-sans.txt` | `LICENSE` | `8ed5cd9e189e30dfdb0df2d5c2771556b50e9d502d899221328c3245caf8423c` |
| `OFL-public-sans.txt` | `LICENSE` | `705a497c781f6463ff819abb513bb495f3fb05256f1d20321e3275813c0bafa5` |
| `OFL-catamaran.txt` | `LICENSE` | `fd38c84fcccb579c579ae5cf6dd3a621305cb42144979c82a6d7cec9985b31cd` |
| `OFL-nunito.txt` | `LICENSE` | `40991bfa02ac620aae16dc527f3c47765a25e43f270d4c301ee6ab663a8d9015` |

## Updating

`curl -sfo <file> https://cdn.jsdelivr.net/npm/@fontsource/<family>@<version>/files/<family>-latin-<weight>-normal.woff2`, then update the table (`sha256sum`) and `fonts.css`. Only `.woff2` is served (static manifest allowlist); the licence and this file stay on disk.
