// Child-process and socket helpers shared by the runner. Every helper bounds its own wait so
// a hung kernel cannot hang the acceptance run.
import net from 'node:net'
import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { checkPortFree } from './ports.mjs'

const execFileAsync = promisify(execFile)

// One-shot execution with a timeout. Resolves with exit code, captured output and the last
// JSON line when the program printed one; never throws for a non-zero exit.
export async function runOnce(command, args, timeoutMs, { env } = {}) {
  const started = performance.now()
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, ...env } })
    return { exit: 0, timedOut: false, stdout, stderr, json: lastJson(stdout), durationMs: Math.round(performance.now() - started) }
  } catch (error) {
    return {
      exit: error.code ?? 1,
      timedOut: Boolean(error.killed),
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? error.message,
      json: lastJson(error.stdout ?? ''),
      durationMs: Math.round(performance.now() - started),
    }
  }
}

// Runs a probe that prints one JSON line on stdout and exits 0 for both accept and reject;
// exit 0 with no JSON means the probe itself failed to report.
export async function runJson(command, args, timeoutMs) {
  const result = await runOnce(command, args, timeoutMs)
  return { ...result, json: result.json ?? lastJson(result.stdout) }
}

function lastJson(stdout) {
  for (const line of stdout.trim().split('\n').reverse()) {
    try {
      return JSON.parse(line)
    } catch {
      // keep looking for the last JSON line
    }
  }
  return null
}

// Polls until the loopback port accepts a connection. Returns early when the child exits.
export async function waitConnectable({ host = '127.0.0.1', port, timeoutMs = 15000 }, timeout, exitPromise) {
  const deadline = performance.now() + timeoutMs
  while (performance.now() < deadline) {
    const probe = await probePort(host, port, 500)
    if (probe === 'connect') return { ok: true, reason: null }
    const settled = await Promise.race([exitOf(exitPromise), sleep(100).then(() => null)])
    if (settled) return { ok: false, reason: `kernel exited before becoming ready (${JSON.stringify(settled)})` }
  }
  return { ok: false, reason: `proxy endpoint did not accept connections within ${timeoutMs} ms` }
}

export async function waitPortFree(port, timeoutMs = 5000) {
  const deadline = performance.now() + timeoutMs
  while (performance.now() < deadline) {
    if (await checkPortFree(port)) return true
    await sleep(100)
  }
  return false
}

function exitOf(promise) {
  return Promise.race([promise, new Promise((never) => setTimeout(never, 60000))])
}

function sleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms))
}

function probePort(host, port, timeoutMs) {
  return new Promise((resolveProbe) => {
    const socket = net.connect({ host, port })
    const done = (result) => {
      socket.destroy()
      resolveProbe(result)
    }
    socket.setTimeout(timeoutMs, () => done('timeout'))
    socket.once('connect', () => done('connect'))
    socket.once('error', () => done('error'))
  })
}

// A single HTTP CONNECT request through a proxy. The returned handle waits for the tunnel
// response head, then writes one tagged request and waits for a complete response before
// closing. Payload bytes pass through untouched; the caller decides what they mean.
export function openTunnel({ method = 'CONNECT', host, port, target, connectTimeoutMs = 5000, connectHeadPattern = null }) {
  return new Promise((resolveExchange) => {
    let socket = net.connect({ host, port })
    let buffered = ''
    let finished = false
    const listeners = new Set()
    const notify = () => {
      for (const listener of listeners) listener()
    }
    const settle = (value) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      socket.destroy()
      resolveExchange(value)
    }
    const timer = setTimeout(() => {
      const error = new Error(`no response within ${connectTimeoutMs} ms`)
      error.name = 'TimeoutError'
      settle({ error })
    }, connectTimeoutMs)
    socket.setEncoding('utf8')
    socket.setNoDelay(true)
    socket.on('data', (chunk) => {
      buffered += chunk
      notify()
    })
    socket.on('error', (error) => settle({ error }))
    socket.on('close', () => {
      if (!finished) settle({ error: Object.assign(new Error('connection closed before the response head'), { name: 'ClosedError' }) })
    })
    const authority = `${target.host}:${target.port}`
    socket.once('connect', () => {
      socket.write(`${method} ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
    })
    const headPattern = connectHeadPattern ?? /\r\n\r\n/
    waitUntil(() => matchIndex(buffered, headPattern), () => buffered, connectTimeoutMs).then((match) => {
      const head = match.startsWith('HTTP/') ? match : buffered.slice(0, buffered.indexOf(match))
      if (finished) return
      clearTimeout(timer)
      finished = true
      const status = Number(/^HTTP\/\S+\s+(\d+)/.exec(head)?.[1] ?? 0)
      let consumed = head.length + 4
      const live = socket
      resolveExchange({
        error: null,
        response: { status, head },
        // Writes one request and resolves with the exact response bytes that follow the
        // CONNECT head. Headers and body length are taken from the response itself.
        async write(payload, timeoutMs) {
          live.write(payload)
          await waitUntil(() => completeResponseLength(buffered.slice(consumed)) > 0, () => buffered, timeoutMs)
          const text = buffered.slice(consumed)
          const length = completeResponseLength(text)
          const slice = text.slice(0, length)
          consumed += length
          return slice
        },
        close() {
          return new Promise((resolveClose) => {
            live.end()
            live.once('close', resolveClose)
            setTimeout(resolveClose, 500)
          })
        },
      })
    }, (error) => settle({ error }))
  })
}

// Total byte length of one complete HTTP response at the start of text, or 0 when the
// response is not complete yet. HEAD, 204 and 304 carry no body.
function completeResponseLength(text) {
  const end = text.indexOf('\r\n\r\n')
  if (end < 0) return 0
  const head = text.slice(0, end)
  const status = Number(/^HTTP\/\S+\s+(\d+)/.exec(head)?.[1] ?? 0)
  if (status === 204 || status === 304) return end + 4
  const length = Number(/content-length: *(\d+)/i.exec(head)?.[1] ?? 0)
  const required = end + 4 + length
  return text.length >= required ? required : 0
}

// Resolves with the first value the predicate accepts, or rejects on timeout or source error.
function waitUntil(predicate, source, timeoutMs) {
  return new Promise((resolveWait, rejectWait) => {
    const start = performance.now()
    const poll = () => {
      const value = predicate()
      if (value) {
        cleanup()
        resolveWait(value)
      } else if (performance.now() - start > timeoutMs) {
        cleanup()
        const error = new Error(`no response within ${timeoutMs} ms`)
        error.name = 'TimeoutError'
        rejectWait(error)
      } else setTimeout(poll, 20)
    }
    const cleanup = () => clearTimeout(handle)
    const handle = setTimeout(poll, 0)
    poll()
    void source
  })
}

function waitFor(predicate, timeoutMs) {
  return new Promise((resolveWait, rejectWait) => {
    const start = performance.now()
    const poll = () => {
      if (predicate()) resolveWait()
      else if (performance.now() - start > timeoutMs) {
        const error = new Error(`no response within ${timeoutMs} ms`)
        error.name = 'TimeoutError'
        rejectWait(error)
      } else setTimeout(poll, 20)
    }
    poll()
  })
}

// Stops a child: SIGTERM first, SIGKILL after the grace period, and waits for exit.
export async function killProcess(child, exited, graceMs = 5000) {
  if (child.exitCode !== null || child.signalCode !== null) return { code: child.exitCode, signal: child.signalCode, forced: false }
  child.kill('SIGTERM')
  const graceful = await Promise.race([exited, sleep(graceMs).then(() => null)])
  if (graceful) return { ...graceful, forced: false }
  child.kill('SIGKILL')
  const forced = await Promise.race([exited, sleep(2000).then(() => ({ code: null, signal: 'SIGKILL' }))])
  return { ...forced, forced: true }
}

export async function runUntilExit(child, timeoutMs) {
  const exited = new Promise((resolveExit) => child.once('exit', (code, signal) => resolveExit({ code, signal })))
  return Promise.race([exited, sleep(timeoutMs).then(() => null)])
}

// Returns the matched text once the pattern matches the buffer, otherwise an empty string.
function matchIndex(buffer, pattern) {
  return new RegExp(pattern.source, pattern.flags.replace('g', '').replace('y', '')).exec(buffer)?.[0] ?? ''
}

// Runs a child that prints one JSON object and exits; used for helpers and probes whose
// output decides the next step rather than the result.
export async function spawnJson(command, args, { env, timeoutMs = 10000 } = {}) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } })
  let stdout = ''
  let stderr = ''
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk })
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk })
  const exited = await runUntilExit(child, timeoutMs)
  if (!exited) {
    await killProcess(child, Promise.resolve({ code: null, signal: 'SIGKILL' }), 0)
    return { exit: null, timedOut: true, stdout, stderr, json: lastJson(stdout) }
  }
  return { exit: exited.code, timedOut: false, stdout, stderr, json: lastJson(stdout) }
}
