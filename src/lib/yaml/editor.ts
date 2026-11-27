/**
 * CodeMirror 6 YAML editor for profiles and overrides. Loaded on demand by
 * YamlEditor.vue so the main bundle does not carry the editor.
 */
import {
  acceptCompletion,
  autocompletion,
  closeBrackets,
  closeBracketsKeymap,
  completionKeymap,
  snippetCompletion,
  type Completion,
  type CompletionContext,
  type CompletionResult as CmCompletionResult,
} from '@codemirror/autocomplete'
import { javascript } from '@codemirror/lang-javascript'
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands'
import { yaml } from '@codemirror/lang-yaml'
import {
  bracketMatching,
  foldGutter,
  foldKeymap,
  HighlightStyle,
  indentOnInput,
  indentUnit,
  syntaxHighlighting,
  syntaxTree,
} from '@codemirror/language'
import { linter, lintGutter, type Diagnostic } from '@codemirror/lint'
import { highlightSelectionMatches, search, searchKeymap } from '@codemirror/search'
import { Compartment, EditorSelection, EditorState } from '@codemirror/state'
import {
  Decoration,
  drawSelection,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
  MatchDecorator,
  placeholder as placeholderExt,
  ViewPlugin,
  type DecorationSet,
  type ViewUpdate,
} from '@codemirror/view'
import { tags } from '@lezer/highlight'
import { complete, type KnownNames } from './complete'
import { RULE_TYPES } from './schema'
import { tr } from '../i18n'
import { completeConfigAccess, SCRIPT_SNIPPETS, type OverrideLanguage } from './script'

export interface YamlEditorOptions {
  doc: string
  readOnly?: boolean
  placeholder?: string
  label?: string
  names?: () => KnownNames
  /** Edits a 覆写: offer `+key` / `key+` / `key!` modifiers. */
  override?: boolean
  language?: OverrideLanguage
  onChange?: (value: string) => void
  onSave?: () => void
}

export interface YamlEditorHandle {
  view: EditorView
  getValue(): string
  setValue(value: string): void
  setReadOnly(readOnly: boolean): void
  setLanguage(language: OverrideLanguage): void
  focus(): void
  destroy(): void
}

/** Colours come from the app tokens, so light/dark follow the theme without a second palette. */
const highlight = HighlightStyle.define([
  { tag: [tags.definition(tags.propertyName), tags.propertyName], color: 'var(--accent-ink)' },
  { tag: [tags.string, tags.special(tags.string)], color: 'var(--good-ink)' },
  { tag: tags.content, color: 'var(--text)' },
  { tag: [tags.lineComment, tags.comment], color: 'var(--text-3)', fontStyle: 'italic' },
  { tag: [tags.labelName, tags.typeName, tags.meta], color: 'var(--data-up)' },
  { tag: [tags.separator, tags.punctuation, tags.brace, tags.squareBracket], color: 'var(--text-3)' },
  { tag: tags.keyword, color: 'var(--data-up)' },
  { tag: [tags.number, tags.bool, tags.null, tags.atom], color: 'var(--fair-ink)' },
  { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: 'var(--accent-ink)' },
  { tag: [tags.regexp, tags.escape], color: 'var(--poor-ink)' },
  { tag: tags.operator, color: 'var(--text-2)' },
])

const scalarMark = Decoration.mark({ class: 'cm-yaml-scalar' })
const ruleMark = Decoration.mark({ class: 'cm-yaml-rule' })
const RULE_PATTERN = RULE_TYPES.map((rule) => rule.replace(/-/g, '\\-')).join('|')

/** Plain scalars are one token in the YAML grammar; tint booleans, numbers and rule types. */
const scalarDecorator = new MatchDecorator({
  regexp: new RegExp(
    `(?<=(?::|^\\s*-)\\s+)(?:true|false|null|~|-?\\d+(?:\\.\\d+)?)(?=\\s*(?:#.*)?$)|(?<=^\\s*-\\s+['"]?)(?:${RULE_PATTERN})(?=,)`,
    'gm',
  ),
  decoration: (match) => (/^[A-Z]/.test(match[0]) ? ruleMark : scalarMark),
})

const scalars = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet
    constructor(view: EditorView) {
      this.decorations = scalarDecorator.createDeco(view)
    }
    update(update: ViewUpdate) {
      this.decorations = scalarDecorator.updateDeco(update, this.decorations)
    }
  },
  { decorations: (plugin) => plugin.decorations },
)

/** Parser error nodes as diagnostics; the backend still validates on save. */
function treeErrors(view: EditorView, message: string): Diagnostic[] {
  const diagnostics: Diagnostic[] = []
  syntaxTree(view.state).iterate({
    enter(node) {
      if (!node.type.isError) return
      const from = Math.max(0, Math.min(node.from, view.state.doc.length))
      const to = Math.min(view.state.doc.length, Math.max(node.to, from + 1))
      diagnostics.push({ from, to, severity: 'error', message })
    },
  })
  return diagnostics.slice(0, 50)
}

const yamlLinter = linter((view) => treeErrors(view, tr('YAML 语法有误')), { delay: 400 })

/** Syntax check only; runtime errors come from the backend preview. */
const scriptLinter = linter(
  (view) => {
    const located = treeErrors(view, tr('脚本语法有误'))
    if (located.length) return located.slice(0, 1)
    const code = view.state.doc.toString()
    if (!code.trim()) return []
    try {
      // Parsing only: the function is never called.
      new Function(code)
      return []
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const lineNo = Number((error as { line?: number }).line)
      const line = view.state.doc.line(Number.isInteger(lineNo) && lineNo >= 1 && lineNo <= view.state.doc.lines ? lineNo : view.state.doc.lines)
      return [{ from: line.from, to: Math.min(view.state.doc.length, Math.max(line.to, line.from + 1)), severity: 'error', message: `${tr('脚本语法有误')}：${message}` }]
    }
  },
  { delay: 500 },
)

function scriptSnippets(): Completion[] {
  return SCRIPT_SNIPPETS.map((item) =>
    snippetCompletion(item.snippet, { label: item.label, detail: tr(item.detail), type: 'text' }),
  )
}

function scriptSource(context: CompletionContext): CmCompletionResult | null {
  const line = context.state.doc.lineAt(context.pos)
  const before = context.state.sliceDoc(line.from, context.pos)
  const access = completeConfigAccess(before)
  if (access) {
    return {
      from: line.from + access.from,
      options: access.options.map((option) => ({ label: option.label, apply: option.apply, detail: option.detail, type: option.type })),
      filter: false,
    }
  }
  const word = context.matchBefore(/[\w.$]+/)
  if (!word && !context.explicit) return null
  return { from: word?.from ?? context.pos, options: scriptSnippets(), validFor: /^[\w.$ ]*$/ }
}

const languageExtensions = (language: OverrideLanguage) =>
  language === 'javascript' ? [javascript(), scriptLinter] : [yaml(), scalars, yamlLinter]

const theme = EditorView.theme({
  '&': { height: '100%', fontSize: 'var(--text-md)', backgroundColor: 'var(--sunken)', color: 'var(--text)' },
  '&.cm-focused': { outline: 'none' },
  '.cm-scroller': { fontFamily: 'var(--mono)', lineHeight: '1.6' },
  '.cm-content': { padding: '10px 0', caretColor: 'var(--accent)' },
  '.cm-line': { padding: '0 12px 0 6px' },
  '.cm-gutters': { backgroundColor: 'var(--sunken)', color: 'var(--text-3)', border: 'none', borderRight: '1px solid var(--border)' },
  '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--text)' },
  '.cm-activeLine': { backgroundColor: 'var(--hover)' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--accent)' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: 'var(--accent-soft) !important' },
  '.cm-selectionMatch': { backgroundColor: 'var(--accent-soft)' },
  '.cm-matchingBracket': { outline: '1px solid var(--border-strong)', backgroundColor: 'transparent' },
  '.cm-foldGutter .cm-gutterElement': { padding: '0 4px', cursor: 'pointer' },
  '.cm-foldPlaceholder': { backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-3)', padding: '0 6px', borderRadius: '4px' },
  '.cm-placeholder': { color: 'var(--text-3)' },
  '.cm-yaml-scalar': { color: 'var(--fair-ink)' },
  '.cm-yaml-rule': { color: 'var(--data-up)', fontWeight: '600' },
  '.cm-tooltip': { backgroundColor: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '8px', boxShadow: 'var(--shadow-md)', overflow: 'hidden' },
  '.cm-tooltip-autocomplete > ul': { fontFamily: 'var(--mono)', maxHeight: '16em' },
  '.cm-tooltip-autocomplete > ul > li': { padding: '3px 10px 3px 6px', lineHeight: '1.6' },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': { backgroundColor: 'var(--accent-soft)', color: 'var(--text)' },
  '.cm-completionDetail': { marginLeft: '12px', fontFamily: 'var(--font)', fontStyle: 'normal', color: 'var(--text-3)' },
  '.cm-completionMatchedText': { textDecoration: 'none', color: 'var(--accent-ink)', fontWeight: '650' },
  '.cm-panels': { backgroundColor: 'var(--surface)', color: 'var(--text)' },
  '.cm-panels.cm-panels-bottom': { borderTop: '1px solid var(--border)' },
  '.cm-search': { fontFamily: 'var(--font)', fontSize: 'var(--text-sm)' },
  '.cm-search input, .cm-search button': { fontFamily: 'var(--font)' },
  '.cm-textfield': { backgroundColor: 'var(--sunken)', border: '1px solid var(--border-strong)', borderRadius: '6px', color: 'var(--text)' },
  '.cm-button': { backgroundImage: 'none', backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--text)' },
  '.cm-diagnostic-error': { borderLeftColor: 'var(--poor)' },
  '.cm-lintRange-error': { backgroundImage: 'none', textDecoration: 'underline wavy var(--poor)', textUnderlineOffset: '3px' },
})

export function createYamlEditor(parent: HTMLElement, options: YamlEditorOptions): YamlEditorHandle {
  let currentText = options.doc
  let language: OverrideLanguage = options.language ?? 'yaml'
  const editable = new Compartment()
  const languageConf = new Compartment()
  const readOnlyState = (readOnly: boolean) => [EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]

  const source = (context: CompletionContext) => {
    if (language === 'javascript') return scriptSource(context)
    const result = complete(currentText, context.pos, options.names?.() ?? {}, Boolean(options.override))
    if (!result) return null
    // Only pop up unprompted once the user typed something or just finished `: `, `- ` or `,`.
    if (!context.explicit && result.from === context.pos) {
      const before = context.state.sliceDoc(Math.max(0, context.pos - 2), context.pos)
      if (!/(: |- |,)$/.test(before)) return null
    }
    return {
      from: result.from,
      // Keep the engine's order (config groups before built-ins, prefix before substring).
      options: result.options.map((option, index) => ({
        label: option.label,
        apply: option.apply,
        detail: option.detail,
        type: option.type,
        boost: Math.max(-99, 99 - index),
      })),
      validFor: /^[\w一-龥.+!<>-]*$/,
    }
  }

  let applying = false
  const view = new EditorView({
    parent,
    state: EditorState.create({
      doc: options.doc,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightSpecialChars(),
        history(),
        foldGutter({ openText: '▾', closedText: '▸' }),
        drawSelection(),
        indentOnInput(),
        bracketMatching(),
        closeBrackets(),
        highlightActiveLine(),
        highlightSelectionMatches(),
        search({ top: false }),
        EditorState.tabSize.of(2),
        indentUnit.of('  '),
        languageConf.of(languageExtensions(language)),
        syntaxHighlighting(highlight),
        lintGutter(),
        autocompletion({ override: [source], icons: false, activateOnTyping: true, maxRenderedOptions: 80 }),
        keymap.of([
          { key: 'Mod-s', preventDefault: true, run: () => (options.onSave?.(), true) },
          // Tab accepts a suggestion first, then indents.
          { key: 'Tab', run: acceptCompletion },
          ...closeBracketsKeymap,
          ...completionKeymap,
          ...searchKeymap,
          ...foldKeymap,
          ...historyKeymap,
          ...defaultKeymap,
          indentWithTab,
        ]),
        editable.of(readOnlyState(Boolean(options.readOnly))),
        options.placeholder ? placeholderExt(options.placeholder) : [],
        EditorView.contentAttributes.of({ 'aria-label': options.label ?? 'YAML', spellcheck: 'false', autocapitalize: 'off', autocorrect: 'off' }),
        EditorView.updateListener.of((update) => {
          if (!update.docChanged) return
          currentText = update.state.doc.toString()
          if (!applying) options.onChange?.(currentText)
        }),
        theme,
      ],
    }),
  })

  return {
    view,
    getValue: () => currentText,
    setValue(value: string) {
      if (value === currentText) return
      applying = true
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: value },
        selection: EditorSelection.cursor(Math.min(view.state.selection.main.head, value.length)),
      })
      applying = false
    },
    setReadOnly(readOnly: boolean) {
      view.dispatch({ effects: editable.reconfigure(readOnlyState(readOnly)) })
    },
    setLanguage(next: OverrideLanguage) {
      if (next === language) return
      language = next
      view.dispatch({ effects: languageConf.reconfigure(languageExtensions(next)) })
    },
    focus: () => view.focus(),
    destroy: () => view.destroy(),
  }
}
