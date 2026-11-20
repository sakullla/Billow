// Minimal YAML block-mapping editing for the two top level keys the runner overrides
// (mixed-port and external-controller). Fixtures use plain unquoted keys and scalar values;
// line-based edits avoid a YAML dependency in the acceptance path. Nested keys with the same
// name keep their indentation and are untouched.
export function setTopLevel(text, key, value) {
  const lines = text.replace(/\r\n/g, '\n').split('\n')
  // Only a column-0 key is a top level key; nested keys keep their indentation.
  const pattern = new RegExp(`^${key.replace(/[-.]/g, '\\$&')}\\s*:`)
  const index = lines.findIndex((line) => pattern.test(line))
  const line = `${key}: ${value}`
  if (index >= 0) {
    lines[index] = line
    return lines.join('\n')
  }
  const firstMappingIndex = lines.findIndex((entry) => /^[\w-]+\s*:/.test(entry))
  const insertAt = firstMappingIndex >= 0 ? firstMappingIndex : 0
  lines.splice(insertAt, 0, line)
  return lines.join('\n')
}

export function getTopLevel(text, key) {
  const match = new RegExp(`^${key.replace(/[-.]/g, '\\$&')}\\s*:\\s*(.*)$`, 'm').exec(text)
  return match ? match[1].trim() : null
}
