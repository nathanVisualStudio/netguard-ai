const { app, BrowserWindow, dialog } = require('electron')
const { spawn } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const net = require('net')
const path = require('path')

const serviceDir = path.join(__dirname, '..', 'service')
const token = crypto.randomBytes(24).toString('hex')
const dev = process.argv.includes('--dev')
let service = null

function pythonBinary() {
  if (process.env.NETGUARD_PYTHON) return process.env.NETGUARD_PYTHON
  const win = process.platform === 'win32'
  const venv = win
    ? path.join(serviceDir, '.venv', 'Scripts', 'python.exe')
    : path.join(serviceDir, '.venv', 'bin', 'python')
  if (fs.existsSync(venv)) return venv
  return win ? 'python' : 'python3'
}

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer()
    probe.on('error', reject)
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
}

function startService(port) {
  service = spawn(
    pythonBinary(),
    ['-m', 'uvicorn', 'netguard.api:app', '--host', '127.0.0.1', '--port', String(port)],
    { cwd: serviceDir, env: { ...process.env, NETGUARD_TOKEN: token }, stdio: ['ignore', 'inherit', 'inherit'] }
  )
  service.on('error', () => {
    dialog.showErrorBox(
      'Python not found',
      'NetGuard AI needs Python 3.10+ with the packages from service/requirements.txt. Set NETGUARD_PYTHON to the interpreter path if needed.'
    )
    app.quit()
  })
}

function stopService() {
  if (service && !service.killed) service.kill()
  service = null
}

async function createWindow() {
  const port = await freePort()
  startService(port)

  const win = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#f3efe6',
    autoHideMenuBar: true,
    title: 'NetGuard AI',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      additionalArguments: [`--ng-port=${port}`, `--ng-token=${token}`],
      contextIsolation: true,
      nodeIntegration: false,
    },
  })

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('http://localhost:5173') && !url.startsWith('file://')) event.preventDefault()
  })

  if (dev) win.loadURL('http://localhost:5173')
  else win.loadFile(path.join(__dirname, '..', 'frontend', 'dist', 'index.html'))
}

app.whenReady().then(createWindow)
app.on('before-quit', stopService)
app.on('window-all-closed', () => {
  stopService()
  app.quit()
})
