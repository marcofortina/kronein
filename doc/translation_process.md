# Kronein translation process

Kronein Core uses Qt Linguist catalogs for its graphical interface and for
selected messages emitted by the core application. Catalog filenames retain
the inherited `bitcoin_<locale>.ts` convention for now; the filename is an
internal build detail and is not user-facing branding.

Kronein does not currently use the upstream Bitcoin Transifex project. The
upstream `.tx/config` was removed so that a translation sync cannot overwrite
Kronein terminology. A dedicated hosted translation service may be configured
later.

## Writing translatable code

- In GUI source under `src/qt`, use `tr("...")`.
- In non-GUI source under `src`, use `_("...")`.
- Do not translate internal errors, logs, RPC field names, or developer-only
  strings.

The source catalogs must use one of these inherited filename forms:

```text
bitcoin_xx.ts
bitcoin_xx_YY.ts
```

`src/qt/locale/bitcoin_en.ts` is the canonical source catalog. To regenerate
it after changing source strings, configure a build with Qt Linguist and
gettext available, then run:

```sh
cmake --build build --target translate -j8
```

This also updates `src/qt/bitcoinstrings.cpp` and
`src/qt/locale/bitcoin_en.xlf`.

## Updating translations

Edit affected `.ts` catalogs with Qt Linguist or as reviewed XML changes.
Preserve placeholders such as `%1`, `%n`, `%s`, and markup exactly. Proper
names use `Kronein`, while monetary unit labels use `KNE`, `mKNE`, and `µKNE`.
The user-facing PSBT expansion is “Partially Signed Kronein Transaction,” and
payment requests use the `kronein:` URI scheme. The PSBT acronym and data
format remain compatible with the inherited Bitcoin Core implementation.

Validate every catalog by compiling the translation resources:

```sh
cmake --build build --target release_translations -j8
```

New languages must be added to `src/qt/bitcoin_locale.qrc`. The resource entry
references the compiled `.qm` file, not the source `.ts` file.

## Review policy

Translation changes are submitted to the Kronein repository together with the
source strings they update. Brand substitutions must be checked in every
catalog so that a localized interface cannot fall back to Bitcoin branding.
