const { base, token } = window.netguard
const headers = { 'X-Token': token }

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function parse(res) {
  if (res.ok) return res
  let message = 'Request failed'
  try {
    const body = await res.json()
    if (typeof body.detail === 'string') message = body.detail
    else if (Array.isArray(body.detail)) message = 'Invalid input'
  } catch {
    message = `Service error (${res.status})`
  }
  throw new Error(message)
}

export async function waitForService(attempts = 80) {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(`${base}/api/health`, { headers })
      if (res.ok) return
    } catch {
      continue
    }
    await pause(400)
  }
  throw new Error('service unavailable')
}

export async function localNetwork() {
  const res = await parse(await fetch(`${base}/api/local-network`, { headers }))
  return (await res.json()).cidr
}

export async function runScan(target, ports) {
  const res = await parse(
    await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, ports }),
    })
  )
  return res.json()
}

export async function savePdf(reportId) {
  const res = await parse(await fetch(`${base}/api/report/${reportId}/pdf`, { headers }))
  const url = URL.createObjectURL(await res.blob())
  const link = document.createElement('a')
  link.href = url
  link.download = 'netguard-report.pdf'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 15000)
}
