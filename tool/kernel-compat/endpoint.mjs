// Controlled echo endpoint. It listens on loopback only, records each request's raw head,
// received body and a structured value, and answers with a JSON receipt. Payload bytes are
// counted, not interpreted as YAML or commands.
import http from 'node:http'

export async function startEcho({ host = '127.0.0.1', port = 0 } = {}) {
  const requests = []
  const server = http.createServer((request, response) => {
    const chunks = []
    request.on('data', (chunk) => chunks.push(chunk))
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      let value = null
      try {
        const parsed = JSON.parse(body)
        value = typeof parsed.marker === 'string' ? parsed.marker : null
      } catch {
        value = null
      }
      const receipt = {
        method: request.method,
        path: request.url,
        headers: request.headers,
        bodyBytes: body.length,
        value,
        at: new Date().toISOString(),
      }
      requests.push(receipt)
      response.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' })
      response.end(JSON.stringify({ marker: value, receivedBytes: body.length, path: request.url }))
    })
  })
  server.keepAliveTimeout = 1000
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen({ host, port }, resolveListen)
  })
  const { port: boundPort } = server.address()
  return {
    host,
    port: boundPort,
    requests,
    clear() {
      requests.length = 0
    },
    close: () => new Promise((resolveClose) => server.close(() => resolveClose())),
  }
}
