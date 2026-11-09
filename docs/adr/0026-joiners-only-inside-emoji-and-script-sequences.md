# ADR 0026: ZWJ/ZWNJ and presentation selectors only inside emoji / complex-script sequences

**TL;DR:** The display-text policy (`domain/text.py`, shared by item titles/descriptions and every alert field) keeps ZWJ/ZWNJ only between two chars that *take* a joiner (emoji or complex-script letters/marks) and VS15/VS16 only after an emoji base. Outgoing text is also secret-scanned with every Default_Ignorable char removed. Blank look-alikes gain U+FFFC, U+16FE4, U+1D159. Fixes backlog G4 items 1-2.

## Context

- The old rule kept ZWJ/ZWNJ between *any* two visible chars and VS15/VS16 after *any* visible char, so emoji and Indic/Persian text worked.
- The S-D review (verified) showed that this also passes `Y<ZWJ>e<VS16>s` as an option label (it renders as "Yes" but carries hidden data), and an AWS key with a ZWJ between each char passes `MessageContent` *and* the secret scan: the regex rules are ASCII, and no scanned form removed the joiners.
- `unicodedata` has no Script or Emoji property, so "where a joiner is needed" has to be approximated.

## Decision

- **One policy, extended in place** (`_strip_invisible`, so `sanitize_line`, `sanitize_description`, `sanitize_outgoing_line` and `reject_invisible` stay one rule):
  - ZWJ/ZWNJ are kept only if the char before (or a kept VS16) and the char after both satisfy `unicode.takes_joiner`: So/Sk symbols from U+2000 up (emoji, skin tones, ♀/♂), or letters/marks outside the Latin/Greek/Cyrillic/Armenian blocks and their extension, fullwidth and math forms. ASCII never qualifies.
  - VS15/VS16 are kept only after `unicode.takes_presentation_selector`: a non-ASCII symbol or punctuation, U+2139, or `#*0-9` directly followed by keycap U+20E3.
- **Scan a joiner-free copy:** `application/notify.scan_texts` also feeds each text with all Default_Ignorable chars removed (plain and NFKC).
- **Cut titles cleanly:** `events/base.compose_text` trims a trailing joiner/selector with the cut (`text.trim_cut_end`), so a rendered alert always passes `reject_invisible`.
- **More blank look-alikes:** U+FFFC, U+16FE4, U+1D159 are added to `BLANK_LOOKALIKES`. The Hangul fillers were already Default_Ignorable.

## Consequences

- Item titles and descriptions follow the same stricter rule, so publish's sanitized-form scan (C15) also sees ZWJ-split tokens whole. Stored titles are re-sanitized on read, so no migration is needed: they only lose meaningless joiners.
- Rare legitimate uses are lost: ZWJ ligature requests in Latin text, a selector after a Latin or CJK letter, and joiners between an emoji and a letter.
- `BLANK_LOOKALIKES` is also used by path validation (C7) and MCP error sanitizing: file names containing the new chars are now refused.
- The block list is an approximation. A new Latin-like block would count as "complex" until it is listed. The joiner-free scan copy covers secret detection regardless.
