// 파릇 계정 저장 API — Vercel 서버리스 함수
// 저장소: Upstash Redis (Vercel Storage에서 연결하면 환경변수가 자동으로 들어옵니다)
const crypto = require('crypto');

const URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const YEAR = 60 * 60 * 24 * 365;

// 다른 프로젝트와 같은 저장소를 쓰므로 모든 키 앞에 paroot: 을 붙여요
const PREFIX = 'paroot:';
async function redis(op, key, ...rest) {
  const r = await fetch(URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify([op, PREFIX + key, ...rest]),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const norm = (id) => String(id || '').trim().toLowerCase();
const fail = (res, code, error) => res.status(code).json({ error });

async function userFromToken(token) {
  if (!token || typeof token !== 'string' || token.length > 100) return null;
  return redis('GET', `tok:${token}`);
}
async function newToken(id) {
  const token = crypto.randomBytes(24).toString('hex');
  await redis('SET', `tok:${token}`, id, 'EX', YEAR);
  return token;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return fail(res, 405, 'POST만 받아요');
  if (!URL || !TOKEN) return fail(res, 503, '저장 서버가 아직 연결되지 않았어요');

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};
  const { action } = body;

  try {
    if (action === 'register' || action === 'login') {
      const id = norm(body.id), pw = String(body.pw || '');
      if (!/^[a-z0-9가-힣_]{3,20}$/.test(id)) return fail(res, 400, '아이디는 영문, 숫자, 한글, 밑줄로 3~20자예요');
      if (pw.length < 6 || pw.length > 100) return fail(res, 400, '비밀번호는 6자 이상이에요');

      const tries = await redis('INCR', `rl:${id}`);
      if (tries === 1) await redis('EXPIRE', `rl:${id}`, 600);
      if (tries > 15) return fail(res, 429, '시도가 너무 많았어요. 10분 뒤에 다시 해주세요');

      const raw = await redis('GET', `user:${id}`);
      if (action === 'register') {
        if (raw) return fail(res, 409, '이미 있는 아이디예요. 로그인하거나 다른 아이디를 써주세요');
        const salt = crypto.randomBytes(16).toString('hex');
        await redis('SET', `user:${id}`, JSON.stringify({ salt, hash: hash(pw, salt), created: Date.now() }));
        if (body.data) {
          const d = JSON.stringify(body.data);
          if (d.length < 400000) await redis('SET', `data:${id}`, d);
        }
        return res.json({ id, token: await newToken(id) });
      }
      if (!raw) return fail(res, 404, '없는 아이디예요. 새 계정을 만들어 주세요');
      const u = JSON.parse(raw);
      const ok = crypto.timingSafeEqual(Buffer.from(hash(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
      if (!ok) return fail(res, 401, '비밀번호가 맞지 않아요');
      await redis('DEL', `rl:${id}`);
      const data = await redis('GET', `data:${id}`);
      return res.json({ id, token: await newToken(id), data: data ? JSON.parse(data) : null });
    }

    const id = await userFromToken(body.token);
    if (!id) return fail(res, 401, '다시 로그인해 주세요');

    if (action === 'pull') {
      const data = await redis('GET', `data:${id}`);
      return res.json({ id, data: data ? JSON.parse(data) : null });
    }
    if (action === 'push') {
      const d = JSON.stringify(body.data || null);
      if (!body.data || !Array.isArray(body.data.plants)) return fail(res, 400, '저장할 정원이 없어요');
      if (d.length > 400000) return fail(res, 413, '저장 데이터가 너무 커요');
      // 더 오래된 저장본이 최신본을 덮지 않도록
      const cur = await redis('GET', `data:${id}`);
      if (cur) { try { if ((JSON.parse(cur).savedAt || 0) > (body.data.savedAt || 0)) return res.json({ ok: true, skipped: true }); } catch {} }
      await redis('SET', `data:${id}`, d);
      return res.json({ ok: true });
    }
    if (action === 'logout') {
      await redis('DEL', `tok:${body.token}`);
      return res.json({ ok: true });
    }
    return fail(res, 400, '알 수 없는 요청이에요');
  } catch (e) {
    return fail(res, 500, '저장 서버에 문제가 생겼어요. 잠시 뒤에 다시 해주세요');
  }
};
