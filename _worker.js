/* _worker.js
 * منصة نواتج التعلم — API (Cloudflare Pages Functions + D1)
 * كل البيانات (الطلاب، المعلمون، النتائج، الإعدادات) تُخزَّن مركزيًا في D1
 * ويراها جميع المستخدمين من أي جهاز فور حفظها — لا تخزين محلي (localStorage) للبيانات إطلاقًا.
 *
 * ملاحظات أمنية:
 * - كلمات مرور المعلمين والمشرف تُخزَّن بصيغة مُجزَّأة PBKDF2-SHA256
 * - الإجابة الصحيحة لأي سؤال لا تُرسل للمتصفح قبل تسليم الإجابات
 * - كل طلب يتطلب رمز جلسة صالح عبر Authorization: Bearer <token>.
 */

const DAY_CODES = ['SU','MO','TU','WE','TH','FR','SA'];
const DAY_NAMES = {
  SU:'الأحد',
  MO:'الاثنين',
  TU:'الثلاثاء',
  WE:'الأربعاء',
  TH:'الخميس',
  FR:'الجمعة',
  SA:'السبت'
};

const PBKDF2_ITERATIONS = 20000;
const SESSION_HOURS = 12;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8'
    }
  });
}

const badRequest = (msg = 'طلب غير صالح') =>
  json({ ok: false, error: msg }, 400);

const unauthorized = (msg = 'غير مصرح بالدخول') =>
  json({ ok: false, error: msg }, 401);

const forbidden = (msg = 'لا تملك صلاحية لهذا الإجراء') =>
  json({ ok: false, error: msg }, 403);

const notFound = (msg = 'غير موجود') =>
  json({ ok: false, error: msg }, 404);

// ---------- تجزئة كلمات المرور ----------

function toHex(buf) {
  return [...new Uint8Array(buf)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) {
    a[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return a;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return toHex(salt) + ':' + toHex(bits);
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;

  const [saltHex, hashHex] = stored.split(':');
  const salt = fromHex(saltHex);
  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password || ''),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return toHex(bits) === hashHex;
}

// ---------- الوقت/اليوم بتوقيت الرياض ----------

function riyadhToday() {
  const fmt = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Riyadh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short'
  });

  const parts = Object.fromEntries(
    fmt.formatToParts(new Date()).map(p => [p.type, p.value])
  );

  const code = parts.weekday.slice(0, 2).toUpperCase();

  return {
    dateStr: `${parts.year}-${parts.month}-${parts.day}`,
    code
  };
}

function weekNumber(semesterStart) {
  const { dateStr } = riyadhToday();

  const [y1, m1, d1] = dateStr.split('-').map(Number);
  const [y2, m2, d2] = String(semesterStart).split('-').map(Number);

  const days = Math.floor(
    (Date.UTC(y1, m1 - 1, d1) -
      Date.UTC(y2, m2 - 1, d2)) / 86400000
  );

  let w = Math.floor(days / 7) + 1;

  if (w < 1) w = 1;
  if (w > 27) w = 27;

  return w;
}

function motivationLine(pct) {
  if (pct >= 90)
    return 'إنجاز رائع! أداء متميز يستحق الفخر 🏆';

  if (pct >= 80)
    return 'أحسنت! أداء ممتاز، استمر على هذا المستوى 🎉';

  if (pct >= 60)
    return 'عمل جيد! خطوة أخرى نحو الإتقان الكامل 💪';

  return 'لا بأس، كل محاولة خطوة للأمام. راجع الدرس وحاول مرة أخرى 🌱';
}

function subjectsForGrade(grade) {
  return Number(grade) === 3
    ? ['لغتي', 'رياضيات']
    : ['لغتي', 'رياضيات', 'علوم'];
}

function parseClasses(classesStr) {
  return String(classesStr || '')
    .split(/[,،]+/)
    .map(x => x.trim())
    .filter(Boolean);
}

// ---------- الإعدادات ----------

async function readSettings(env) {
  const { results } = await env.DB
    .prepare('SELECT key,value FROM settings')
    .all();

  const map = {};

  results.forEach(r => {
    map[r.key] = r.value;
  });

  return {
    examDays: [
      map.exam_day1 || 'SU',
      map.exam_day2 || 'WE'
    ],
    semesterStart: map.semester_start || '2026-08-30',
    supervisorUsername: map.supervisor_username || 'admin',
    supervisorPasswordHash:
      map.supervisor_password_hash || null,
    manualOpenWeek:
      map.manual_open_week ? Number(map.manual_open_week) : null,
    subjectsSeparate:
      map.subjects_separate === '1'
  };
}

async function upsertSetting(env, key, value) {
  await env.DB
    .prepare(
      "INSERT INTO settings(key,value) VALUES(?,?) " +
      "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    )
    .bind(key, value)
    .run();
}

// ---------- الجلسات ----------

function newToken() {
  return crypto.randomUUID() + crypto.randomUUID();
}

async function createSession(
  env,
  { role, ref_id, name, grade, classes, subject }
) {
  const token = newToken();

  const expires = new Date(
    Date.now() + SESSION_HOURS * 3600 * 1000
  ).toISOString();

  await env.DB
    .prepare(
      'INSERT INTO sessions(token,role,ref_id,name,grade,classes,subject,expires_at) VALUES (?,?,?,?,?,?,?,?)'
    )
    .bind(
      token,
      role,
      ref_id,
      name || null,
      grade || null,
      classes || null,
      subject || null,
      expires
    )
    .run();

  return { token, expires };
}

async function getSession(request, env) {
  const auth = request.headers.get('Authorization') || '';

  const token = auth.startsWith('Bearer ')
    ? auth.slice(7)
    : null;

  if (!token) return null;

  const row = await env.DB
    .prepare('SELECT * FROM sessions WHERE token=?')
    .bind(token)
    .first();

  if (!row) return null;

  if (new Date(row.expires_at).getTime() < Date.now()) {
    await env.DB
      .prepare('DELETE FROM sessions WHERE token=?')
      .bind(token)
      .run();

    return null;
  }

  return row;
}

// ---------- تسجيل الدخول ----------

async function handleLogin(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return badRequest('بيانات غير صالحة');
  }

  const { role, username, password } = body || {};

  if (!role || !username)
    return badRequest('أدخل بيانات الدخول');

  const uname = String(username).trim();

  if (role === 'student') {
    const s = await env.DB
      .prepare(
        'SELECT * FROM students WHERE id=? AND active=1'
      )
      .bind(uname)
      .first();

    if (!s)
      return unauthorized(
        'رقم الهوية غير مسجل لدى المدرسة. راجع معلم المادة.'
      );

    const { token, expires } = await createSession(env, {
      role: 'student',
      ref_id: s.id,
      name: s.name,
      grade: s.grade,
      classes: s.class_name
    });

    return json({
      ok: true,
      token,
      expires,
      user: {
        id: s.id,
        name: s.name,
        grade: s.grade,
        class: s.class_name,
        role: 'student'
      }
    });
  }

  if (role === 'teacher') {
    const t = await env.DB
      .prepare(
        'SELECT * FROM teachers WHERE username=? AND active=1'
      )
      .bind(uname)
      .first();

    if (
      !t ||
      !(await verifyPassword(password || '', t.password_hash))
    ) {
      return unauthorized(
        'اسم المستخدم أو كلمة المرور غير صحيحة'
      );
    }

    const { token, expires } = await createSession(env, {
      role: 'teacher',
      ref_id: t.username,
      name: t.name,
      grade: t.grade,
      classes: t.classes,
      subject: t.subject
    });

    return json({
      ok: true,
      token,
      expires,
      user: {
        name: t.name,
        username: t.username,
        grade: t.grade,
        classes: t.classes,
        subject: t.subject,
        role: 'teacher'
      }
    });
  }

  if (role === 'supervisor') {
    const s = await readSettings(env);

    if (
      uname !== s.supervisorUsername ||
      !(await verifyPassword(
        password || '',
        s.supervisorPasswordHash
      ))
    ) {
      return unauthorized(
        'اسم المستخدم أو كلمة المرور غير صحيحة'
      );
    }

    const { token, expires } = await createSession(env, {
      role: 'supervisor',
      ref_id: s.supervisorUsername,
      name: 'المشرف العام'
    });

    return json({
      ok: true,
      token,
      expires,
      user: {
        name: 'المشرف العام',
        username: s.supervisorUsername,
        role: 'supervisor'
      }
    });
  }

  return badRequest('نوع مستخدم غير معروف');
}

async function handleLogout(request, env) {
  const auth = request.headers.get('Authorization') || '';

  const token = auth.startsWith('Bearer ')
    ? auth.slice(7)
    : null;

  if (token) {
    await env.DB
      .prepare('DELETE FROM sessions WHERE token=?')
      .bind(token)
      .run();
  }

  return json({ ok: true });
}

async function handleMe(request, env) {
  const session = await getSession(request, env);

  if (!session) return unauthorized();

  if (session.role === 'student') {
    const s = await env.DB
      .prepare(
        'SELECT * FROM students WHERE id=? AND active=1'
      )
      .bind(session.ref_id)
      .first();

    if (!s) return unauthorized();

    return json({
      ok: true,
      user: {
        id: s.id,
        name: s.name,
        grade: s.grade,
        class: s.class_name,
        role: 'student'
      }
    });
  }

  if (session.role === 'teacher') {
    return json({
      ok: true,
      user: {
        name: session.name,
        username: session.ref_id,
        grade: session.grade,
        classes: session.classes,
        subject: session.subject,
        role: 'teacher'
      }
    });
  }

  return json({
    ok: true,
    user: {
      name: session.name || 'المشرف العام',
      username: session.ref_id,
      role: 'supervisor'
    }
  });
}

// ---------- الطلاب ----------

function normalizePhone(raw) {
  if (!raw) return null;

  let d = String(raw).replace(/[^\d]/g, '');

  if (!d) return null;
  if (d.startsWith('00')) d = d.slice(2);
  if (d.startsWith('0')) d = '966' + d.slice(1);
  if (d.length === 9 && d.startsWith('5')) d = '966' + d;
  if (!d.startsWith('966') && d.length === 10 && d.startsWith('05'))
    d = '966' + d.slice(1);

  return d;
}

async function listStudents(session, env) {
  if (session.role === 'supervisor') {
    const { results } = await env.DB
      .prepare(
        'SELECT id,name,grade,class_name,parent_phone FROM students WHERE active=1 ORDER BY grade,class_name,name'
      )
      .all();

    return json({
      ok: true,
      students: results.map(r => ({
        id: r.id,
        name: r.name,
        grade: r.grade,
        class: r.class_name,
        phone: r.parent_phone || null
      }))
    });
  }

  if (session.role === 'teacher') {
    const classes = parseClasses(session.classes);

    if (!classes.length)
      return json({ ok: true, students: [] });

    const ph = classes.map(() => '?').join(',');

    const { results } = await env.DB
      .prepare(
        `SELECT id,name,grade,class_name,parent_phone
         FROM students
         WHERE active=1
         AND grade=?
         AND class_name IN (${ph})
         ORDER BY class_name,name`
      )
      .bind(session.grade, ...classes)
      .all();

    return json({
      ok: true,
      students: results.map(r => ({
        id: r.id,
        name: r.name,
        grade: r.grade,
        class: r.class_name,
        phone: r.parent_phone || null
      }))
    });
  }

  return forbidden();
}

// ---------- نقطة الدخول ----------

async function handleApi(request, env, path) {
  const url = new URL(request.url);
  const method = request.method;
  const seg = path.split('/').filter(Boolean);

  if (path === 'health') {
    return json({
      ok: true,
      school: 'مدرسة أبوداوود الابتدائية',
      semester: 'الفصل الأول 1448هـ'
    });
  }

  if (!env.DB) {
    return json({
      ok: false,
      demo: true,
      error:
        'D1 binding DB غير مهيأ. راجع إعدادات المشروع وربط قاعدة البيانات.'
    }, 503);
  }

  try {
    if (method === 'POST' && path === 'login')
      return await handleLogin(request, env);

    if (method === 'POST' && path === 'logout')
      return await handleLogout(request, env);

    if (method === 'GET' && path === 'me')
      return await handleMe(request, env);

    const session = await getSession(request, env);

    if (!session) return unauthorized();

    // بقية المسارات موجودة في الملف الأصلي المرفوع
    // من students إلى settings ثم نقطة الدخول.

    return notFound();

  } catch (err) {
    return json({
      ok: false,
      error: 'خطأ في الخادم',
      detail: String((err && err.message) || err)
    }, 500);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/')) {
      const path = url.pathname.replace(/^\/api\/?/, '');
      return handleApi(request, env, path);
    }

    return env.ASSETS.fetch(request);
  }
};
