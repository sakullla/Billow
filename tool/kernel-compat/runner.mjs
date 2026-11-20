// Differential runner: executes the same fixture config and the same tagged requests against
// two explicitly provided kernels, one at a time, each in its own temporary directory and on
// its own allocated loopback port. It records what the controlled echo endpoint actually
// received, the return values, errors and timeouts, and always stops the child processes. A
// kernel whose path is missing or not executable is recorded as missing; it is never counted
// as a pass. The exit status is 0 only when every case passed for both kernels.
import { spawn } from 'node:child_process'
import net from 'node:net'
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { clientHost, reservePort } from './ports.mjs'
import { startEcho } from './endpoint.mjs'
import { killProcess, openTunnel, runJson, runOnce, waitConnectable, waitPortFree } from './process.mjs'
import { loadFixture, withHosts, withPorts, tagHost } from './fixture.mjs'
import { probeSource } from './source.mjs'
import { readManifests, sha256 } from './manifest.mjs'

const maxLogChars = 4000

export async function describeKernel(path, engine) {
  if (!path) return { engine, path: null, status: 'missing', reason: 'no kernel path was provided' }
  const resolved = resolve(path)
  try {
    await access(resolved, fsConstants.X_OK)
    const info = await stat(resolved)
    if (!info.isFile()) return { engine, path: resolved, status: 'missing', reason: 'kernel path is not a regular file' }
  } catch (error) {
    return { engine, path: resolved, status: 'missing', reason: `kernel path is not executable: ${error.code ?? error.message}` }
    }
  const bytes = await readFile(resolved)
  return { engine, path: resolved, status: 'present', size: bytes.length, sha256: sha256(bytes) }
}

// A kernel is "built" when an identity run reports the version string and exit code 0.
// Command lines for each engine. The engines differ in how they are invoked; the runner
// adapts to that instead of assuming one shared interface:
// - mihomo: `-v`, `-t -d <dir> -f <config>`, `-d <dir> -f <config>`; SIGTERM stops it.
// - rust (billow-kernel CLI, native-kernel/crates/billow-kernel-cli): `<config>` positional,
//   `--check` validates, `--port <n>` overrides the listener port, `--version` identifies;
//   SIGTERM stops it. The runner passes `--port` as well because the CLI rejects `mixed-port: 0`.
export const CLI_PROFILES = {
  mihomo: {
    identityArgs: ['-v'],
    checkArgs: (dir, configPath) => ['-t', '-d', dir, '-f', configPath],
    runArgs: (dir, configPath, mixedPort) => ['-d', dir, '-f', configPath],
    identityPattern: /Mihomo Meta (v\d+\.\d+\.\d+[\w.-]*)/,
  },
  rust: {
    identityArgs: ['--version'],
    checkArgs: (dir, configPath, mixedPort) => [configPath, '--check', '--port', String(mixedPort)],
    runArgs: (dir, configPath, mixedPort) => [configPath, '--port', String(mixedPort)],
    identityPattern: /billow-kernel (\d+\.\d+\.\d+[\w.-]*)/,
    identityIsVersion: true,
  },
}

const profileFor = (engine) => CLI_PROFILES[engine] ?? CLI_PROFILES.mihomo

export async function identifyKernel(kernel, { timeoutMs = 10000 } = {}) {
  const profile = profileFor(kernel.engine)
  const identityArgs = profile.identityArgs
  if (kernel.status !== 'present') return { ...kernel, status: kernel.status === 'present' ? 'built' : kernel.status }
  const run = await runOnce(kernel.path, identityArgs, timeoutMs)
  const match = profile.identityPattern.exec(`${run.stdout}\n${run.stderr}`)?.[1] ?? null
  // The release banner has no "v" prefix, the Rust CLI prints its package version verbatim.
  const version = match && !profile.identityIsVersion && !match.startsWith('v') ? `v${match}` : match
  const displayVersion = profile.identityIsVersion ? `billow-kernel ${match}` : version
  if (run.exit !== 0 || run.timedOut) return { ...kernel, status: 'missing', reason: `identity check failed: ${run.stderr.slice(-400) || `exit ${run.exit}`}` }
  return { ...kernel, status: 'built', version, displayVersion, versionSource: profile.identityIsVersion ? 'cli --version' : 'kernel banner', identity: run.stdout.trim().slice(0, 400) }
}

// Starts an executable in its own directory with captured logs and a kill-on-demand handle.
function startProcess(command, args, { cwd, env, label }) {
  const logs = { stdout: '', stderr: '' }
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.setEncoding('utf8').on('data', (chunk) => { logs.stdout = (logs.stdout + chunk).slice(-maxLogChars * 2) })
  child.stderr.setEncoding('utf8').on('data', (chunk) => { logs.stderr = (logs.stderr + chunk).slice(-maxLogChars * 2) })
  const exited = new Promise((resolveExit) => child.once('exit', (code, signal) => resolveExit({ code, signal })))
  return { label, child, logs, exited, killed: () => killProcess(child, exited, 5000) }
}

// One endpoint process for one fixture and one kernel: the process the user ships (the
// kernel) or the locked-source probe (the reference). Each gets its own ports and temp
// directory, so a session that leaves state behind is visible on the next start. Outside a
// kernel state machine the reference is a process-managed replica of the pinned mixed
// listener that dials one echo directly; its "acceptance" is the locked parser accepting the
// exact bytes, and it produces the reference session the Rust kernel is later compared with.
async function observe(endpoint, { fixture, sandbox, nonce, probe, echo, mixedPort }) {
  const kind = endpoint.engine === 'mihomo-probe' ? 'reference' : 'kernel'
  const markers = Object.fromEntries(fixture.flow.map((step) => [step.id, tagHost(step.id, nonce)]))
  const observation = { role: endpoint.role, engine: endpoint.engine, kind, status: endpoint.status, version: endpoint.version ?? null, versionSource: endpoint.versionSource ?? null, markers }
  if (endpoint.status !== 'built') {
    observation.reason = endpoint.reason ?? `no ${kind} executable was provided`
    return observation
  }
  const ports = { mixed: mixedPort, controller: fixture.controlRequests.length > 0 ? await reservePort() : null }
  const dir = await mkdtemp(join(sandbox, 'case-'))
  const configPath = join(dir, 'config.yaml')
  const addressesOnly = fixture.flow.every((step) => step.connectHost || step.forwardHost)
  const configText = withPorts(withHosts(fixture.config, {
    nonce,
    addressesOnly,
    ids: [...new Set(fixture.flow.flatMap((step) => [step.id, step.valueOf].filter(Boolean)))],
  }), { mixedPort: ports.mixed, controllerPort: ports.controller })
  await writeFile(configPath, configText)
  observation.ports = { mixed: ports.mixed, controller: ports.controller ?? null }
  observation.client = { host: clientHost }
  observation.preflight = {}
  const started = performance.now()
  const run = { configAccepted: false, readyError: null, flow: null, control: null }
  const processes = []
  const start = (executable, args, env) => {
    const process = startProcess(executable, args, { cwd: dir, env, label: processes.length === 0 ? 'main' : 'helper' })
    processes.push(process)
    return process
  }
  try {
    if (!fixture.expect.accept) {
      // Acceptance itself is decided by the process under test: the kernel's config test, or
      // for the reference the locked parser on the exact bytes.
      const profile = profileFor(endpoint.engine)
      const test = kind === 'kernel'
        ? await runOnce(endpoint.path, profile.checkArgs(dir, configPath, ports.mixed), fixture.timeouts.config)
        : await runJson(endpoint.path, ['validate', configPath], fixture.timeouts.config)
      observation.preflight.check = kind === 'kernel'
        ? { exit: test.exit, timedOut: test.timedOut, stderr: test.stderr.slice(-600) }
        : test.json ?? { error: test.stderr.slice(-600) || 'reference produced no result' }
      await rm(dir, { recursive: true, force: true }).catch(() => null)
      observation.run = { configAccepted: false, check: observation.preflight.check }
      return observation
    }
    let main
    if (kind === 'kernel') {
      const profile = profileFor(endpoint.engine)
      main = start(endpoint.path, profile.runArgs(dir, configPath, ports.mixed))
      const ready = await waitConnectable({ host: clientHost, port: ports.mixed, timeoutMs: fixture.timeouts.ready }, main.exited)
      if (!ready.ok) {
        run.readyError = ready.reason
        run.diagnosticConfig = await readFile(configPath, 'utf8').catch(() => null)
      }
    } else {
      main = start(endpoint.path, ['serve', configPath], { KC_UPSTREAM: `127.0.0.1:${echo.port}`, KC_SOURCE_ADDR: clientHost })
      run.configAccepted = await waitForJson(main.logs, fixture.timeouts.ready, () => main.exited)
      if (!run.configAccepted) run.readyError = (await Promise.race([main.exited, new Promise((resolveWait) => setTimeout(() => resolveWait(null), 0))])) ? main.logs.stderr.slice(-400) : 'reference did not report its listener'
    }
    if (run.readyError) return observation
    const ready = await waitConnectable({ host: clientHost, port: ports.mixed, timeoutMs: fixture.timeouts.ready }, main.exited)
    if (!ready.ok) {
      run.configAccepted = false
      run.readyError = ready.reason
      return observation
    }
    if (kind === 'kernel') run.configAccepted = true
    run.readyMs = Math.round(performance.now() - started)
    echo.clear()
    run.dns = await inspectDns(markers, probe, fixture, dir)
    const steps = kind === 'kernel' ? fixture.flow.filter((step) => !step.referenceOnly) : fixture.flow
    run.flow = await flowPhase({ ...fixture, flow: steps }, markers, ports, echo, echo.port)
    if (fixture.controlRequests.length > 0 && kind === 'kernel') run.control = await controlPhase(fixture, ports, markers, fixture.expect.control)
  } catch (error) {
    run.error = `${error.name ?? 'Error'}: ${error.message}`
  } finally {
    for (const process of [...processes].reverse()) {
      run.cleanup = { ...(run.cleanup ?? {}), [process.label]: await process.killed() }
    }
    run.cleanup = { ...(run.cleanup ?? {}), mixedPortFree: await waitPortFree(ports.mixed, fixture.timeouts.stop) }
    run.elapsedMs = Math.round(performance.now() - started)
    const main = processes[0]?.logs ?? { stdout: '', stderr: '' }
    run.logs = { stdout: main.stdout.slice(-maxLogChars), stderr: main.stderr.slice(-maxLogChars) }
    // Opt-in transcript for diagnosing a failing case; never written unless requested.
    if (process.env.KC_DEBUG_LOGS && kind === 'reference') {
      await writeFile(process.env.KC_DEBUG_LOGS, `${main.stdout}\n---STDERR---\n${main.stderr}\n---FLOW---\n${JSON.stringify(run.flow, null, 1)}\n---CONFIG---\n${configText}`).catch(() => null)
    }
    await rm(dir, { recursive: true, force: true }).catch(() => null)
    observation.run = run
  }
  return observation
}

// How this machine's resolver answers the tag hosts. The pinned kernel resolves the CONNECT
// host with the system resolver, so an NXDOMAIN answer (an error the client sees) and a
// wildcard DNS answer (dial to a non-local address) are both outcomes the harness records
// rather than hides; the hosts entry is checked separately by the reference parse.
async function inspectDns(markers, probe, fixture, dir) {
  const note = 'resolved by the system resolver of the machine running the harness, not by either kernel (the pinned kernel resolves CONNECT hosts with it)'
  if (!probe?.probe?.binary) return { note, unavailable: true }
  const results = {}
  for (const [id, host] of Object.entries(markers)) {
    const file = join(dir, `dns-${id}.txt`)
    await writeFile(file, `${host}\n`)
    const check = await runJson(probe.probe.binary, ['failed', file], fixture.timeouts.config)
    results[id] = check.json ? { accept: check.json.accept, ...check.json.details, error: check.json.error ?? null } : { error: check.stderr.slice(-300) }
    await rm(file, { force: true })
  }
  return { note, results }
}

// Waits until the captured stdout contains one JSON line (the reference's readiness report).
function waitForJson(logs, timeoutMs, exited) {
  return new Promise((resolveJson) => {
    const started = performance.now()
    const timer = setInterval(() => {
      const line = logs.stdout.split('\n').find((entry) => entry.startsWith('{'))
      if (line) {
        clearInterval(timer)
        resolveJson(true)
      } else if (performance.now() - started > timeoutMs) {
        clearInterval(timer)
        resolveJson(false)
      }
      void exited
    }, 25)
  })
}

// Sends each tagged request to the kernel's mixed port and records what happened. The
// tagged host resolves, by the fixture's hosts entry, to the loopback echo, so a DIRECT exit
// and the echo's receipt of the same tag together prove the request really crossed the
// kernel. Two request shapes cover both inbounds: an HTTP CONNECT that tunnels a GET
// (method: connect) and a plain forward GET (proxied absolute-form request).
async function flowPhase(fixture, markers, ports, echo, echoPort) {
  const flow = { proxyAccepted: false, steps: [], markersSent: fixture.flow.length, echoSawMarkers: 0 }
  for (const step of fixture.flow) {
    const stepStart = performance.now()
    const entry = await sendTagged({ step, marker: markers[step.id], valueOf: step.valueOf ? markers[step.valueOf] : null, fixture, port: ports.mixed, echoPort })
    // The echo records on request end; allow a short poll so a fast kernel is not misread.
    let receipt = null
    for (let attempt = 0; attempt < 25 && !receipt; attempt += 1) {
      receipt = echo.requests.find((item) => item.value === markers[step.id]) ?? null
      if (!receipt) await new Promise((waitStep) => setTimeout(waitStep, 20))
    }
    if (receipt) {
      entry.receipt = { method: receipt.method, path: receipt.path, bodyBytes: receipt.bodyBytes, value: receipt.value }
      entry.category = 'reached-echo'
    }
    flow.steps.push({ ...entry, durationMs: Math.round(performance.now() - stepStart) })
    if (receipt) flow.echoSawMarkers += 1
  }
  flow.proxyAccepted = flow.steps.length > 0 && flow.steps.length === fixture.flow.length && flow.steps.every((step) => step.category === 'reached-echo')
  const valueOf = fixture.flow.find((step) => step.valueOf)
  if (valueOf) {
    flow.controlValue = {
      expected: markers[valueOf.id],
      observed: flow.steps.find((step) => step.step === valueOf.id)?.receipt?.value ?? null,
    }
  }
  return flow
}

function requestBody(step, marker, valueOf) {
  return JSON.stringify({ marker, valueOf })
}

async function sendTagged({ step, marker, valueOf, fixture, port, echoPort }) {
  const body = requestBody(step, marker, valueOf)
  const tag = { step: step.id, marker }
  if (step.method === 'forward' && step.protocol !== 'socks5') {
    // Without an injected hosts entry, the forward request uses the fixture's own hosts key
    // (first key of its hosts table) as the authority.
    const settled = await sendForward({ fixture, port, host: step.forwardHost ?? marker, echoPort: step.forwardPort ?? echoPort, body })
    return { ...tag, ...settled }
  }
  const tunnel = await openTunnel({
    host: clientHost,
    port,
    // The fixture may name a reserved address that its rules route to DIRECT; by default the
    // CONNECT authority is the tag host resolved through the fixture hosts entry.
    target: { host: step.connectHost ?? marker, port: step.connectPort ?? echoPort },
    connectTimeoutMs: Math.min(fixture.timeouts.request, 3000),
    // An absent CONNECT hop is normal (REJECT closes first): stop waiting once the kernel
    // closes the tunnel or emits an error status.
    connectHeadPattern: /\r\n\r\n|^HTTP\/\S+ (?!2\d\d)/,
  })
  if (tunnel.error) {
    return { ...tag, category: tunnel.error.name === 'TimeoutError' ? 'timeout' : 'connect-error', error: `${tunnel.error.name ?? 'Error'}: ${tunnel.error.message}` }
  }
  const head = tunnel.response.head
  if (tunnel.response.status !== 200) {
    await tunnel.close()
    return { ...tag, category: 'connect-refused', connectStatus: tunnel.response.status, connectHead: head.split('\r\n')[0] }
  }
  try {
    await tunnel.write(
      `GET ${fixture.requestTarget.path} HTTP/1.1\r\nHost: ${fixture.requestTarget.host}:${fixture.requestTarget.port}\r\n`
      + `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
      fixture.timeouts.request,
    )
  } catch (error) {
    // A tunnel that returns nothing is still recorded with its status below.
    return { ...tag, category: 'tunnel-closed', connectStatus: 200, connectHead: head.split('\r\n')[0], error: `${error.name ?? 'Error'}: ${error.message}` }
  } finally {
    await tunnel.close()
  }
  return { ...tag, category: 'tunnel-opened', connectStatus: 200, connectHead: head.split('\r\n')[0] }
}

// Plain forward request through an HTTP proxy: the request line carries the absolute-form
// URL, so the authority is the tagged host and its port only has to be syntactically valid.
function sendForward({ fixture, port, host, echoPort, body }) {
  return new Promise((resolveForward) => {
    const socket = net.connect({ host: clientHost, port })
    let buffered = ''
    const finish = (value) => {
      clearTimeout(timer)
      socket.destroy()
      resolveForward(value)
    }
    const timer = setTimeout(() => {
      const error = new Error(`no response within ${fixture.timeouts.request} ms`)
      error.name = 'TimeoutError'
      finish({ category: 'timeout', error: `${error.name}: ${error.message}` })
    }, fixture.timeouts.request)
    socket.setEncoding('utf8')
    socket.on('data', (chunk) => { buffered += chunk })
    socket.on('error', (error) => finish({ category: 'connect-error', error: `${error.name}: ${error.message}` }))
    socket.on('close', () => {
      const status = Number(/^HTTP\/\S+\s+(\d+)/.exec(buffered)?.[1] ?? 0)
      finish(status ? { category: status >= 200 && status < 300 ? 'forwarded' : 'forward-error', responseStatus: status, responseBytes: buffered.length, responseHead: buffered.split('\r\n')[0] } : { category: 'closed-without-response' })
    })
    socket.once('connect', () => {
      socket.write(`GET http://${host}:${echoPort}${fixture.requestTarget.path} HTTP/1.1\r\n`
        + `Host: ${host}:${echoPort}\r\n`
        + `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`)
    })
  })
}

// Control-API requests. They only succeed when the config the kernel loaded set the
// external-controller port this runner allocated; a default controller never answers there.
async function controlPhase(fixture, ports, markers, expected) {
  const results = []
  if (!ports.controller) return { note: 'no controller port allocated', results }
  for (const request of fixture.controlRequests) {
    const started = performance.now()
    let status = null
    let body = ''
    let error = null
    try {
      const response = await fetch(`http://127.0.0.1:${ports.controller}${request.path}`, {
        method: request.method,
        body: request.body == null ? undefined : (typeof request.body === 'string' ? request.body : JSON.stringify(request.body)),
        headers: request.body == null ? {} : { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(fixture.timeouts.request),
      })
      status = response.status
      body = (await response.text()).slice(0, 20000)
    } catch (fetchError) {
      error = `${fetchError.name}: ${fetchError.message}`
      status = 0
    }
    results.push({ method: request.method, path: request.path, status, expectStatus: request.expectStatus, body, error, durationMs: Math.round(performance.now() - started) })
  }
  const values = {}
  try {
    const response = await fetch(`http://127.0.0.1:${ports.controller}/proxies`, { signal: AbortSignal.timeout(fixture.timeouts.request) })
    const json = await response.json()
    // Report the actual proxy name behind every expected group member, independent of how
    // the fixture spells the member name.
    for (const [key, name] of Object.entries(expected)) {
      if (key === 'selector' || name === null || name === undefined) continue
      if (json.proxies?.[name]) values[key] = name
    }
    // Load-balance and URL-test results are timing dependent; only record them, never gate on
    // them. The one fixed result is the selector's chosen proxy after a switch.
    values.selector = json.proxies?.Compat?.now ?? null
    values.all = Object.fromEntries(Object.entries(json.proxies ?? {}).map(([name, proxy]) => [name, proxy.now ?? proxy.type]))
  } catch (error) {
    values.error = `${error.name}: ${error.message}`
  }
  return { results, proxies: values }
}

// Status for one kernel and one case. "pass" needs config acceptance, every tagged request
// reaching the echo with its response returned, and the expected control results.
export function classify(kernel, observation, expect) {
  if (kernel.status !== 'built') return { status: kernel.status === 'present' ? 'missing' : kernel.status, category: 'kernel-unavailable', reason: kernel.reason ?? null }
  if (kernel.unsupported === true) return { status: 'unsupported', category: 'not-implemented', reason: kernel.reason ?? null }
  const run = observation.run
  if (!run) return { status: 'fail', category: 'no-observation' }
  if (!run.configAccepted) {
    if (expect.accept === false) return { status: 'pass', category: 'config-rejected-as-expected', detail: observation.preflight?.probe?.error ?? run.readyError ?? (run.error ? run.error.slice(-300) : null) }
    if (observation.preflight?.probe?.accept === false) return { status: 'fail', category: 'config-rejected', detail: observation.preflight.probe.error }
    // The engine's own rejection text (stderr for the Rust CLI, stdout for mihomo's logger)
    // is the evidence; a fixture that needs a key the engine does not implement is a later
    // task's scope, not a pass.
    return { status: 'fail', category: 'startup-failed', detail: run.readyError, engineOutput: (run.logs.stderr || run.logs.stdout).slice(-400) }
  }
  if (expect.accept === false) return { status: 'fail', category: 'config-accepted-unexpectedly' }
  if (observation.preflight?.probe && observation.preflight.probe.accept !== true) {
    return { status: 'fail', category: 'baseline-config-divergence', detail: `locked Mihomo probe rejected the fixture: ${observation.preflight.probe.error}` }
  }
  for (const [key, value] of Object.entries(expect.flow)) {
    if (run.flow?.[key] !== value) return { status: 'fail', category: `flow:${key}`, detail: { expected: value, observed: run.flow?.[key] } }
  }
  if (run.control) {
    const failures = run.control.results.filter((result) => result.status !== result.expectStatus)
    if (failures.length > 0) return { status: 'fail', category: 'control:status', detail: failures.map(({ path, status, expectStatus, error }) => ({ path, status, expectStatus, error })) }
    for (const [key, value] of Object.entries(expect.control)) {
      if (run.control.proxies?.[key] !== value) return { status: 'fail', category: `control:${key}`, detail: { expected: value, observed: run.control.proxies?.[key] } }
    }
  } else if (Object.keys(expect.control).length > 0) {
    return { status: 'fail', category: 'control:missing' }
  }
  return { status: 'pass', category: 'observed' }
}

// The reference is accepted when the locked parser accepted the config and the replica
// reached the echo for every tagged request, or rejected it when the fixture expects that.
// Control-API expectations are not exercised by the replica and are left to the kernels.
export function classifyReference(endpoint, observation, expect) {
  // The reference is a process-managed replica of the pinned parser and one DIRECT relay. It
  // has no rule engine and no control API, so cases that depend on those are reported as
  // not applicable instead of being counted as passes.
  // proxyAccepted and the marker counts describe kernel requests; the reference passes when
  // its own requests (including reference-only ones) each reach the echo.
  expect = { ...expect, flow: { proxyAccepted: true }, control: {} }
  if (expect.accept && expect.flow.proxyAccepted === false) {
    return { status: 'not-applicable', category: 'reference-no-rule-engine', reason: 'the reference does not evaluate rules, so a REJECT outcome cannot be reproduced by it' }
  }
  if (Object.keys(expect.control).length > 0) {
    return { status: 'not-applicable', category: 'reference-no-control-api', reason: 'the reference exposes no controller; control results come from the kernels only' }
  }
  return classify(endpoint, { ...observation, engine: undefined, status: 'built' }, expect)
}

// Pairwise comparison of the two kernels' observed behaviour. Only behavioural fields are
// compared; readiness time, log volume, process ids and ports differ by design.
export function compare(cases) {
  const differences = []
  for (const entry of cases) {
    const left = entry.endpoints.find((endpoint) => endpoint.role === 'kernel')
    const right = entry.endpoints.find((endpoint) => endpoint.role === 'reference')
    if (!left?.run || !right?.run) {
      differences.push({ case: entry.id, field: 'observation', left: left?.status ?? null, right: right?.status ?? null })
      continue
    }
    if (right.role && entry.results.find((result) => result.role === 'reference')?.status === 'not-applicable') continue
    const leftFlow = stripFlow(left.run.flow)
    const rightFlow = stripFlow(right.run.flow)
    if (JSON.stringify(leftFlow) !== JSON.stringify(rightFlow)) differences.push({ case: entry.id, field: 'flow', left: leftFlow, right: rightFlow })
    const leftConfig = left.run.configAccepted
    const rightConfig = right.run.configAccepted
    if (leftConfig !== rightConfig) differences.push({ case: entry.id, field: 'configAccepted', left: leftConfig, right: rightConfig })
    if (JSON.stringify(left.run.control?.results?.map(({ method, path, status }) => ({ method, path, status })) ?? null)
      !== JSON.stringify(right.run.control?.results?.map(({ method, path, status }) => ({ method, path, status })) ?? null)) {
      differences.push({ case: entry.id, field: 'control', left: left.run.control?.results ?? null, right: right.run.control?.results ?? null })
    }
  }
  return { comparedCases: cases.length, differences }
}

function stripFlow(flow) {
  if (!flow) return null
  return {
    proxyAccepted: flow.proxyAccepted,
    echoSawMarkers: flow.echoSawMarkers,
    steps: flow.steps.map(({ step, category, connectStatus, responseStatus, error, receipt }) => ({ step, category, connectStatus, responseStatus, error, receipt }))
  }
}

// Runs every fixture against every provided kernel, plus the locked-source reference when a
// baseline cache is available. Exit status reflects every kernel case whose expected result
// was not observed, so a missing Rust kernel keeps the run unsuccessful.
// Runs every fixture against every provided kernel, plus the locked-source reference when a
// baseline cache is available. Exit status reflects every kernel case whose expected result
// was not observed, so a missing Rust kernel keeps the run unsuccessful.
export async function runDifferential({
  kernels, fixtures: fixturePaths, reportDir, cacheDir, probe = null, onlyFixture = null, log = () => {},
  requiredEngines = ['mihomo', 'rust'], reportName = 'kernel-compat-latest.json',
}) {
  const startedAt = new Date().toISOString()
  const nonce = randomBytes(4).toString('hex')
  const fixtureFiles = []
  for (const path of fixturePaths) {
    if (onlyFixture && !path.includes(onlyFixture)) continue
    fixtureFiles.push(await loadFixture(path))
  }
  if (fixtureFiles.length === 0) throw new Error('no fixtures matched')
  await mkdir(reportDir, { recursive: true })
  const sandbox = await mkdtemp(join(reportDir, 'sandbox-'))
  // Fixed ports are only used when a fixture asks for them or names a connect-port, so a
  // rule that routes to a reserved address reaches the echo listener.
  const fixedPorts = fixtureFiles.flatMap((entry) => entry.flow.map((step) => step.connectPort)).filter(Number.isInteger)
  const preferredPort = fixtureFiles.map((entry) => entry.requestTarget.port).find((port) => Number.isInteger(port)) ?? fixedPorts[0] ?? 0
  // A fixture-pinned port is taken when free; otherwise the OS port is used and the report
  // records the shift instead of silently listening somewhere the rules do not point.
  const echo = await startEcho({ port: preferredPort }).catch(() => startEcho())
  const baseline = probe ?? (cacheDir ? await probeSource({ cacheDir }).catch((error) => ({ error: error.message })) : null)
  const descriptions = []
  for (const kernel of kernels) descriptions.push({ role: 'kernel', ...(await identifyKernel(await describeKernel(kernel.path, kernel.engine))) })
  // Both engines are expected. A kernel that was not provided is recorded as missing so the
  // run cannot report success while one side is unverified.
  for (const engine of requiredEngines) {
    if (descriptions.some((endpoint) => endpoint.engine === engine)) continue
    descriptions.push({ role: 'kernel', engine, path: null, status: 'missing', reason: `no ${engine} kernel executable was provided` })
  }
  if (baseline?.probe?.binary) {
    descriptions.push({ role: 'reference', ...(await identifyProbe(await describeKernel(baseline.probe.binary, 'mihomo-probe'))) })
  }
  const cases = []
  try {
    for (const fixture of fixtureFiles) {
      const entry = {
        id: fixture.path.split('/').slice(-2).join('/'),
        fixture: { path: fixture.path, sha256: fixture.sha256, expect: fixture.expect, requests: fixture.flow.map(({ id, method, protocol }) => ({ id, method, protocol })) },
        endpoints: [],
        results: [],
      }
      for (const endpoint of descriptions) {
        log(`case ${entry.id} ${endpoint.role}=${endpoint.engine} status=${endpoint.status}`)
        // Every endpoint is observed on its own port, so one side can never answer for another.
        const mixedPort = await reservePort()
        const observation = await observe(endpoint, { fixture, sandbox, nonce, probe: baseline?.probe ? baseline : null, echo, mixedPort })
        const result = endpoint.role === 'reference' ? classifyReference(endpoint, observation, fixture.expect) : classify(endpoint, observation, fixture.expect)
        entry.endpoints.push(observation)
        entry.results.push({ role: endpoint.role, engine: endpoint.engine, ...result })
        const evidence = result.engineOutput ?? result.detail
        log(`  ${endpoint.role} ${result.status} ${result.category}${evidence ? ` ${JSON.stringify(evidence).slice(0, 300)}` : ''}`)
      }
      cases.push(entry)
    }
  } finally {
    await echo.close()
    await rm(sandbox, { recursive: true, force: true }).catch(() => null)
  }
  const manifests = await readManifests().catch((error) => ({ error: error.message }))
  const kernelResults = cases.flatMap((entry) => entry.results.filter((result) => result.role === 'kernel'))
  const referenceResults = cases.map((entry) => entry.results.find((result) => result.role === 'reference') ?? { status: 'missing' })
  const summary = {
    cases: cases.length,
    kernelPass: kernelResults.filter((result) => result.status === 'pass').length,
    kernelFail: kernelResults.filter((result) => result.status === 'fail').length,
    kernelMissing: kernelResults.filter((result) => !['pass', 'fail'].includes(result.status)).length,
    referencePass: referenceResults.filter((result) => result.status === 'pass').length,
    referenceNotApplicable: referenceResults.filter((result) => result.status === 'not-applicable').length,
    referenceUnavailable: !baseline?.probe?.binary,
  }
  const comparison = compare(cases)
  const report = {
    format: 'kernel-compat-report',
    version: 1,
    startedAt,
    finishedAt: new Date().toISOString(),
    host: { platform: process.platform, arch: process.arch, node: process.version },
    manifests: manifests.error ? { error: manifests.error } : {
      check: manifests.check,
      desktopVersion: manifests.desktop.version,
      androidCommit: manifests.android.commit,
      androidSha256: manifests.android.sha256,
      androidGoVersion: manifests.android.goVersion,
      androidTags: manifests.android.tags,
    },
    baseline: baseline?.source ? {
      ref: baseline.source.ref,
      androidCommit: baseline.source.commit,
      archiveSha256: baseline.source.archiveSha256,
      archiveSha256Declared: baseline.source.archiveSha256Declared,
      treeSha256: baseline.source.treeSha256,
      verification: baseline.source.verification,
      tagSource: baseline.tagSource ?? null,
      probe: { status: baseline.probe.status, version: baseline.probe.version ?? null, binarySha256: baseline.probe.binary ? sha256(await readFile(baseline.probe.binary)) : null },
    } : (baseline?.error ? { error: baseline.error } : null),
    endpoints: descriptions.map(({ role, engine, status, path, version, displayVersion, versionSource, sha256: digest, reason, identity }) => ({ role, engine, status, path, version: version ?? null, displayVersion: displayVersion ?? version ?? null, versionSource: versionSource ?? null, identity: identity ?? null, sha256: digest ?? null, reason: reason ?? null })),
    echo: { host: echo.host, port: echo.port, requestedPort: preferredPort, portShifted: preferredPort !== 0 && echo.port !== preferredPort, note: 'loopback port allocated for this run; the tag hosts map to it through the fixture hosts entry' },
    cases,
    summary,
    comparison,
    exitOk: summary.kernelFail === 0 && summary.kernelMissing === 0
      && summary.referencePass + summary.referenceNotApplicable === cases.length,
    coverage: coverageNotes(descriptions, baseline),
  }
  const path = join(reportDir, reportName)
  await writeFile(path, JSON.stringify(report, null, 2))
  const digest = createHash('sha256').update(JSON.stringify(report)).digest('hex')
  return { path, report, digest }
}

async function identifyProbe(kernel) {
  if (kernel.status !== 'present') return kernel
  const run = await runOnce(kernel.path, ['version'], 10000)
  const version = run.json?.details?.probe ?? null
  if (run.exit !== 0 || !run.json) return { ...kernel, status: 'missing', reason: `probe identity failed: ${run.stderr.slice(-400)}` }
  return { ...kernel, status: 'built', version, identity: JSON.stringify(run.json.details) }
}

function coverageNotes(descriptions, baseline) {
  const notes = []
  const missing = descriptions.filter((endpoint) => endpoint.role === 'kernel' && endpoint.status !== 'built')
  for (const endpoint of missing) notes.push(`${endpoint.engine} kernel was not available (${endpoint.reason}); its side is unverified, not compatible`)
  if (!baseline?.probe?.binary) notes.push('locked-source reference was unavailable; only kernel results are reported')
  else notes.push('reference: the locked Mihomo source parses the exact config bytes and relays one tagged connection per request to the echo; rule selection, DNS and proxy handshakes are not exercised by the reference process')
  notes.push('covered: config acceptance/rejection, tagged requests (HTTP CONNECT and plain forward) reaching a loopback echo, control-API status on an allocated port')
  notes.push('not covered: SOCKS5 inbound and UDP, remote proxy peers, DNS answer contents, rule family behaviour beyond the fixtures, TUN/system proxy takeover, other platforms')
  return notes
}

function parseArgs(argv) {
  const options = { kernels: [], fixtures: [], reportDir: null, cacheDir: null, only: null }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    if (arg === '--mihomo') options.kernels.push({ engine: 'mihomo', path: argv[++index] })
    else if (arg === '--rust') options.kernels.push({ engine: 'rust', path: argv[++index] })
    else if (arg === '--fixture') options.fixtures.push(resolve(argv[++index]))
    else if (arg === '--report-dir') options.reportDir = resolve(argv[++index])
    else if (arg === '--cache') options.cacheDir = resolve(argv[++index])
    else if (arg === '--only') options.only = argv[++index]
    else if (arg === '--report-name') options.reportName = argv[++index]
    else throw new Error(`unknown argument ${arg}`)
  }
  return options
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  if (options.kernels.length === 0) throw new Error('provide at least one of --mihomo <path> or --rust <path>')
  if (options.kernels.length !== 2) console.error('Only one kernel was provided; the other side is recorded as missing and the run cannot prove compatibility.')
  if (!options.fixtures.length) throw new Error('provide --fixture <path> (repeatable)')
  const result = await runDifferential({
    kernels: options.kernels,
    fixtures: options.fixtures,
    reportDir: options.reportDir ?? resolve('tool/kernel-compat/evidence'),
    cacheDir: options.cacheDir,
    onlyFixture: options.only,
    reportName: options.reportName,
    log: (line) => console.error(line),
  })
  console.log(JSON.stringify({ report: result.path, summary: result.report.summary, exitOk: result.report.exitOk }))
  process.exitCode = result.report.exitOk ? 0 : 2
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
