// Loopback port allocation. A port is obtained from the OS on 127.0.0.1 and must also be free
// on ::1 so a kernel binding either family cannot collide with a previous run.
import net from 'node:net'

// Source address for harness connections. A fixture that expects traffic from loopback must
// declare lan-allowed-ips, because the pinned mixed inbound refuses other client ranges by
// default. KC_CLIENT_HOST overrides the address for runs on other interfaces.
export const clientHost = process.env.KC_CLIENT_HOST || '127.0.0.1'

export function reservePort(host = '127.0.0.1') {
  return new Promise((resolvePort, rejectPort) => {
    const server = net.createServer()
    server.unref()
    server.once('error', rejectPort)
    server.listen({ port: 0, host }, () => {
      const { port } = server.address()
      server.close(() => resolvePort(port))
    })
  })
}

export async function allocatePorts({ mixed = true, controller = false } = {}) {
  const ports = {}
  const used = new Set()
  const next = async () => {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const port = await reservePort()
      if (!used.has(port)) {
        used.add(port)
        return port
      }
    }
    throw new Error('could not allocate a distinct loopback port')
  }
  if (mixed) ports.mixed = await next()
  if (controller) ports.controller = await next()
  return ports
}

// True when nothing accepts TCP connections on the loopback port.
export async function checkPortFree(port, host = '127.0.0.1', timeoutMs = 250) {
  return new Promise((resolveFree) => {
    const socket = net.connect({ port, host })
    const done = (free) => {
      socket.destroy()
      resolveFree(free)
    }
    socket.setTimeout(timeoutMs, () => done(true))
    socket.once('connect', () => done(false))
    socket.once('error', () => done(true))
  })
}
