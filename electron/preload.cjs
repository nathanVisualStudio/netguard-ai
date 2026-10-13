const { contextBridge } = require('electron')

const arg = (name) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`))
  return hit ? hit.slice(name.length + 3) : ''
}

contextBridge.exposeInMainWorld('netguard', {
  base: `http://127.0.0.1:${arg('ng-port')}`,
  token: arg('ng-token'),
})
