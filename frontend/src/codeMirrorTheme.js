import { tags as t } from '@lezer/highlight'
import { createTheme } from '@uiw/codemirror-themes'

const darkPalette = {
  bg: '#14181f',
  text: '#e8eaed',
  textMuted: '#8a94a6',
  accent: '#e8a33d',
  border: '#2e3642',
  selection: 'rgba(232, 163, 61, 0.25)',
  string: '#8fbf7f',
  keyword: '#e8a33d',
  comment: '#5c6577',
  className: '#5b8dbe',
}

const lightPalette = {
  bg: '#f4f5f7',
  text: '#1a1e27',
  textMuted: '#5c6577',
  accent: '#b5721e',
  border: '#d8dce3',
  selection: 'rgba(181, 114, 30, 0.2)',
  string: '#3f7a3f',
  keyword: '#b5721e',
  comment: '#8a94a6',
  className: '#2f5d82',
}

function buildTheme(mode, palette) {
  return createTheme({
    theme: mode,
    settings: {
      background: palette.bg,
      foreground: palette.text,
      caret: palette.accent,
      selection: palette.selection,
      selectionMatch: palette.selection,
      lineHighlight: 'transparent',
      gutterBackground: palette.bg,
      gutterForeground: palette.textMuted,
      gutterBorder: 'transparent',
      fontFamily: "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
    },
    styles: [
      { tag: t.comment, color: palette.comment, fontStyle: 'italic' },
      { tag: t.string, color: palette.string },
      { tag: [t.keyword, t.controlKeyword, t.moduleKeyword], color: palette.keyword },
      { tag: [t.className, t.typeName], color: palette.className },
      { tag: [t.number, t.bool, t.null], color: palette.accent },
      { tag: t.function(t.variableName), color: palette.className },
      { tag: t.operator, color: palette.textMuted },
      { tag: t.punctuation, color: palette.textMuted },
    ],
  })
}

export const cmDarkTheme = buildTheme('dark', darkPalette)
export const cmLightTheme = buildTheme('light', lightPalette)
