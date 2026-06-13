// ============================================================
// VaultAgent Circle Proxy — Cloudflare Worker
// Deploy: wrangler deploy
// ============================================================

const CIRCLE_API_BASE = 'https://api.circle.com/v1/w3s'

// Wallets stored in Cloudflare KV (persistent across restarts)

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
  })
}

// Encrypt entity secret with Circle's RSA public key
async function getFreshCiphertext(entitySecret, publicKeyPem) {
  // Import Circle's public key
  const pemContents = publicKeyPem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s/g, '')
  const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0))

  const publicKey = await crypto.subtle.importKey(
    'spki',
    binaryDer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  )

  // Encrypt the entity secret
  const secretBytes = hexToBytes(entitySecret)
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    secretBytes
  )

  return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  }
  return bytes
}

async function getPublicKey(apiKey) {
  const res = await fetch(`${CIRCLE_API_BASE}/config/entity/publicKey`, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  })
  const data = await res.json()
  return data?.data?.publicKey
}

function corsHeaders(request) {
  const origin = request ? request.headers.get('Origin') || '*' : '*'
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Content-Type': 'application/json'
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const path = url.pathname

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request) })
    }

    const CIRCLE_API_KEY = env.CIRCLE_API_KEY
    const ENTITY_SECRET = env.ENTITY_SECRET

    try {

      // ── POST /circle/wallet ──────────────────────────────
      if (path === '/circle/wallet' && request.method === 'POST') {
        const { userId } = await request.json()
        if (!userId) return Response.json({ error: 'userId required' }, { headers: corsHeaders(request) })

        // Check KV for existing wallet
        const existing = await env.WALLETS.get(userId)
        if (existing) {
          const wallet = JSON.parse(existing)
          console.log('[Circle] Returning existing wallet for:', userId)
          return Response.json(
            { success: true, ...wallet, userId },
            { headers: corsHeaders(request) }
          )
        }

        // Create new wallet
        const publicKey = await getPublicKey(CIRCLE_API_KEY)

        const ciphertext1 = await getFreshCiphertext(ENTITY_SECRET, publicKey)
        const wsRes = await fetch(`${CIRCLE_API_BASE}/developer/walletSets`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${CIRCLE_API_KEY}` },
          body: JSON.stringify({
            idempotencyKey: uuidv4(),
            entitySecretCiphertext: ciphertext1,
            name: `ArcAgent-${userId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 20)}`
          })
        })
        const wsData = await wsRes.json()
        const walletSetId = wsData?.data?.walletSet?.id
        if (!walletSetId) throw new Error(wsData?.message || 'Could not create wallet set')

        const ciphertext2 = await getFreshCiphertext(ENTITY_SECRET, publicKey)
        const wRes = await fetch(`${CIRCLE_API_BASE}/developer/wallets`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${CIRCLE_API_KEY}` },
          body: JSON.stringify({
            idempotencyKey: uuidv4(),
            entitySecretCiphertext: ciphertext2,
            walletSetId,
            blockchains: ['ARC-TESTNET'],
            count: 1,
            accountType: 'EOA'
          })
        })
        const wData = await wRes.json()
        const address = wData?.data?.wallets?.[0]?.address
        const walletId = wData?.data?.wallets?.[0]?.id
        if (!address) throw new Error(wData?.message || 'Could not get wallet address')

        // Save to KV for persistence
        await env.WALLETS.put(userId, JSON.stringify({ address, walletId }))
        console.log('[Circle] Wallet saved to KV for:', userId)

        return Response.json(
          { success: true, address, walletId, userId },
          { headers: corsHeaders(request) }
        )
      }

      // ── POST /circle/transaction ─────────────────────────
      if (path === '/circle/transaction' && request.method === 'POST') {
        const { walletId, contractAddress, callData, value } = await request.json()
        if (!walletId || !contractAddress) {
          return Response.json({ error: 'walletId and contractAddress required' }, { headers: corsHeaders(request) })
        }

        const publicKey = await getPublicKey(CIRCLE_API_KEY)
        const ciphertext = await getFreshCiphertext(ENTITY_SECRET, publicKey)

        const txRes = await fetch(`${CIRCLE_API_BASE}/developer/transactions/contractExecution`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${CIRCLE_API_KEY}` },
          body: JSON.stringify({
            idempotencyKey: uuidv4(),
            entitySecretCiphertext: ciphertext,
            walletId,
            contractAddress,
            callData,
            feeLevel: 'MEDIUM',
            ...(value && { amount: value })
          })
        })
        const txData = await txRes.json()
        const txId = txData?.data?.id
        if (!txId) throw new Error(txData?.message || 'Transaction failed')

        return Response.json(
          { success: true, txId, state: txData?.data?.state },
          { headers: corsHeaders(request) }
        )
      }

      // ── GET /circle/transaction/:txId ────────────────────
      if (path.startsWith('/circle/transaction/') && request.method === 'GET') {
        const txId = path.split('/').pop()
        const txRes = await fetch(`${CIRCLE_API_BASE}/transactions/${txId}`, {
          headers: { 'Authorization': `Bearer ${CIRCLE_API_KEY}` }
        })
        const txData = await txRes.json()
        return Response.json(
          { data: txData?.data?.transaction },
          { headers: corsHeaders(request) }
        )
      }

      // ── GET /circle/balance/:walletId ────────────────────
      if (path.startsWith('/circle/balance/') && request.method === 'GET') {
        const walletId = path.split('/').pop()
        const balRes = await fetch(`${CIRCLE_API_BASE}/wallets/${walletId}/balances`, {
          headers: { 'Authorization': `Bearer ${CIRCLE_API_KEY}` }
        })
        const balData = await balRes.json()
        return Response.json(balData, { headers: corsHeaders(request) })
      }

      return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders(request) })

    } catch (e) {
      return Response.json({ error: e.message }, { status: 500, headers: corsHeaders(request) })
    }
  }
}