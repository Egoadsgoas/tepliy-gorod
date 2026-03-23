/**
 * Учебный сервер для курсовой (AJAX + JSON CRUD).
 * Запуск: node server.js
 * Затем открыть: http://localhost:3000
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const ROOT = __dirname;
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const DB_PATH = path.join(ROOT, "db.json");

const sessions = new Map(); // token -> { username, csrfToken, exp }

function jsonResponse(res, status, obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function readDB(){
  if(!fs.existsSync(DB_PATH)){
    const initial = {
      users: [],
      properties: [],
      messages: [],
      viewings: [],
      notifications: [],
      calendarEvents: [],
      crmLeads: []
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), "utf8");
  }
  const raw = fs.readFileSync(DB_PATH, "utf8");
  // Некоторые редакторы на Windows сохраняют JSON с BOM в начале файла.
  const normalizedRaw = raw.replace(/^\uFEFF/, "");
  const parsed = JSON.parse(normalizedRaw || "{}");
  parsed.users = Array.isArray(parsed.users) ? parsed.users : [];
  parsed.properties = Array.isArray(parsed.properties) ? parsed.properties : [];
  parsed.messages = Array.isArray(parsed.messages) ? parsed.messages : [];
  parsed.viewings = Array.isArray(parsed.viewings) ? parsed.viewings : [];
  parsed.notifications = Array.isArray(parsed.notifications) ? parsed.notifications : [];
  parsed.calendarEvents = Array.isArray(parsed.calendarEvents) ? parsed.calendarEvents : [];
  parsed.crmLeads = Array.isArray(parsed.crmLeads) ? parsed.crmLeads : [];
  return parsed;
}

function writeDB(db){
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function sha256Hex(input){
  return crypto.createHash("sha256").update(String(input), "utf8").digest("hex");
}

function hashPassword(password, salt){
  // Формат "salt::password" — учебный пример.
  return sha256Hex(String(salt) + "::" + String(password));
}

function sanitizeText(s, maxLen){
  const str = String(s ?? "");
  // Мини-санация, чтобы при выводе не было инъекций.
  return str.replaceAll("<", "&lt;").replaceAll(">", "&gt;").slice(0, maxLen);
}

/** Картинки как data:image/...;base64,... в JSON (до 5 шт., каждая до ~450 КБ). */
function normalizeImages(bodyImages){
  if(!Array.isArray(bodyImages)) return [];
  const allowed = /^data:image\/(jpeg|png|webp|gif);base64,/i;
  const out = [];
  for(const x of bodyImages.slice(0, 5)){
    const s = String(x);
    if(!allowed.test(s)) continue;
    if(s.length > 480000) continue;
    out.push(s);
  }
  return out;
}

function nextMessageId(db){
  const arr = Array.isArray(db.messages) ? db.messages : [];
  return arr.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
}

function nextViewingId(db){
  const arr = Array.isArray(db.viewings) ? db.viewings : [];
  return arr.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
}

function nextNotificationId(db){
  const arr = Array.isArray(db.notifications) ? db.notifications : [];
  return arr.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
}

function nextCalendarEventId(db){
  const arr = Array.isArray(db.calendarEvents) ? db.calendarEvents : [];
  return arr.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
}

function nextCrmLeadId(db){
  const arr = Array.isArray(db.crmLeads) ? db.crmLeads : [];
  return arr.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0) + 1;
}

function parsePreferredDate(value){
  const text = String(value || "").trim();
  if(!text) return null;
  const normalized = text.replace(" ", "T");
  const direct = new Date(normalized);
  if(!Number.isNaN(direct.getTime())) return direct.toISOString();
  return text.slice(0, 40);
}

function makeNotification(db, payload){
  if(!Array.isArray(db.notifications)) db.notifications = [];
  const item = {
    id: nextNotificationId(db),
    type: sanitizeText(payload.type, 20) || "push",
    recipient: sanitizeText(payload.recipient, 120),
    message: sanitizeText(payload.message, 500),
    channel: sanitizeText(payload.channel, 20) || "system",
    owner: sanitizeText(payload.owner, 120),
    relatedType: sanitizeText(payload.relatedType, 40),
    relatedId: Number(payload.relatedId) || null,
    createdAt: new Date().toISOString()
  };
  db.notifications.unshift(item);
  return item;
}

function makeCalendarEvent(db, payload){
  if(!Array.isArray(db.calendarEvents)) db.calendarEvents = [];
  const item = {
    id: nextCalendarEventId(db),
    title: sanitizeText(payload.title, 160),
    startAt: sanitizeText(payload.startAt, 80),
    endAt: sanitizeText(payload.endAt, 80),
    location: sanitizeText(payload.location, 180),
    owner: sanitizeText(payload.owner, 120),
    attendee: sanitizeText(payload.attendee, 120),
    source: sanitizeText(payload.source, 40) || "system",
    status: sanitizeText(payload.status, 24) || "scheduled",
    createdAt: new Date().toISOString()
  };
  db.calendarEvents.unshift(item);
  return item;
}

function makeCrmLead(db, payload){
  if(!Array.isArray(db.crmLeads)) db.crmLeads = [];
  const item = {
    id: nextCrmLeadId(db),
    title: sanitizeText(payload.title, 160),
    channel: sanitizeText(payload.channel, 40) || "site",
    stage: sanitizeText(payload.stage, 40) || "new",
    owner: sanitizeText(payload.owner, 120),
    contactName: sanitizeText(payload.contactName, 120),
    contactPhone: sanitizeText(payload.contactPhone, 40),
    contactEmail: sanitizeText(payload.contactEmail, 120),
    notes: sanitizeText(payload.notes, 600),
    sourceId: Number(payload.sourceId) || null,
    sourceType: sanitizeText(payload.sourceType, 40),
    createdAt: new Date().toISOString()
  };
  db.crmLeads.unshift(item);
  return item;
}

function parseBody(req){
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => { data += chunk; });
    req.on("end", () => {
      if(!data.trim()){
        resolve({});
        return;
      }
      try{
        resolve(JSON.parse(data));
      }catch(e){
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function getSessionFromReq(req){
  const auth = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/.exec(auth);
  if(!m) return null;
  const token = m[1];
  const session = sessions.get(token);
  if(!session) return null;
  if(Date.now() > session.exp){
    sessions.delete(token);
    return null;
  }
  return session;
}

function mustAuth(req, res){
  const session = getSessionFromReq(req);
  if(!session){
    jsonResponse(res, 401, { ok:false, message: "Unauthorized" });
    return null;
  }
  // CSRF для защищенных мутаций
  const csrf = req.headers["x-csrf-token"] || "";
  if(!csrf || csrf !== session.csrfToken){
    jsonResponse(res, 403, { ok:false, message: "CSRF token mismatch" });
    return null;
  }
  return session;
}

function nextUserId(db){
  return db.users.reduce((m, u) => Math.max(m, Number(u.id) || 0), 0) + 1;
}

/** Гарантирует системные аккаунты и корректные роли пользователей. */
function ensureSystemUsers(){
  const db = readDB();
  let changed = false;

  for(const u of db.users){
    if(!u.role){
      u.role = "client";
      changed = true;
    }
  }

  const demo = db.users.find(u => u.username === "demo");
  if(demo){
    if(demo.role !== "agent"){
      demo.role = "agent";
      changed = true;
    }
    if(hashPassword("demo123", demo.salt) !== demo.passwordHash){
      demo.salt = crypto.randomBytes(16).toString("hex");
      demo.passwordHash = hashPassword("demo123", demo.salt);
      changed = true;
    }
  }else{
    const salt = crypto.randomBytes(16).toString("hex");
    db.users.push({
      id: nextUserId(db),
      username: "demo",
      salt,
      passwordHash: hashPassword("demo123", salt),
      createdAt: new Date().toISOString(),
      role: "agent"
    });
    changed = true;
  }

  const admin = db.users.find(u => u.username === "admin");
  if(admin){
    if(admin.role !== "admin"){
      admin.role = "admin";
      changed = true;
    }
    if(hashPassword("admin123", admin.salt) !== admin.passwordHash){
      admin.salt = crypto.randomBytes(16).toString("hex");
      admin.passwordHash = hashPassword("admin123", admin.salt);
      changed = true;
    }
  }else{
    const adminSalt = crypto.randomBytes(16).toString("hex");
    db.users.push({
      id: nextUserId(db),
      username: "admin",
      salt: adminSalt,
      passwordHash: hashPassword("admin123", adminSalt),
      createdAt: new Date().toISOString(),
      role: "admin"
    });
    changed = true;
  }

  if(changed) writeDB(db);
}

function seedPropertiesIfEmpty(){
  const db = readDB();
  if(db.properties.length > 0) return;

  const now = new Date();
  const demoOwner = "demo";
  const sample = [
    {
      title: "Уютная квартира рядом с метро",
      type: "Квартира",
      address: "Москва, ул. Примерная, д. 12",
      rooms: 2,
      area: 54.2,
      price: 9900000,
      description: "Теплая, светлая квартира. Чистый подъезд, рядом школы и магазины."
    },
    {
      title: "Дом с участком для семьи",
      type: "Дом",
      address: "Подмосковье, п. Зеленый, ул. Садовая, д. 7",
      rooms: 4,
      area: 120.0,
      price: 18500000,
      description: "Участок, беседка, место под парковку. Отличная транспортная доступность."
    },
    {
      title: "Комната в центре города",
      type: "Комната",
      address: "Санкт-Петербург, Невский проспект, д. 44",
      rooms: 1,
      area: 19.6,
      price: 3200000,
      description: "Удобная локация, развитая инфраструктура, чистая кухня на этаже."
    },
    {
      title: "Коммерческое помещение под офис",
      type: "Коммерция",
      address: "Казань, ул. Баумана, д. 3",
      rooms: 3,
      area: 72.5,
      price: 12500000,
      description: "Помещение с ремонтом, отдельный вход, витринные окна."
    }
  ];

  for(const item of sample){
    db.properties.push({
      id: db.properties.length + 1,
      owner: demoOwner,
      createdAt: new Date(now.getTime() - Math.floor(Math.random()*100000000)).toISOString(),
      updatedAt: null,
      ...item
    });
  }
  writeDB(db);
}

function seedDemoIntegrations(){
  const db = readDB();
  let changed = false;
  const demoProperty = db.properties.find((p) => p.owner === "demo") || db.properties[0];
  if(!demoProperty){
    return;
  }

  if(!Array.isArray(db.viewings)) db.viewings = [];
  if(!Array.isArray(db.calendarEvents)) db.calendarEvents = [];
  if(!Array.isArray(db.crmLeads)) db.crmLeads = [];
  if(!Array.isArray(db.notifications)) db.notifications = [];
  if(!Array.isArray(db.messages)) db.messages = [];

  if(db.viewings.length === 0){
    db.viewings.push({
      id: nextViewingId(db),
      propertyId: demoProperty.id,
      propertyTitle: demoProperty.title,
      owner: demoProperty.owner,
      requester: "Анна Петрова",
      phone: "+7 923 555-10-20",
      preferredDate: "2026-03-26 15:00",
      comment: "Хочет посмотреть объект после работы.",
      status: "new",
      createdAt: "2026-03-23T04:10:00.000Z"
    });
    changed = true;
  }

  if(db.calendarEvents.length === 0){
    makeCalendarEvent(db, {
      title: "Просмотр: " + demoProperty.title,
      startAt: "2026-03-26T15:00:00.000Z",
      endAt: "2026-03-26T16:00:00.000Z",
      location: demoProperty.address,
      owner: demoProperty.owner,
      attendee: "Анна Петрова",
      source: "demo-seed",
      status: "scheduled"
    });
    changed = true;
  }

  if(db.crmLeads.length === 0){
    makeCrmLead(db, {
      title: "Лид по просмотру: " + demoProperty.title,
      channel: "site",
      stage: "scheduled",
      owner: demoProperty.owner,
      contactName: "Анна Петрова",
      contactPhone: "+7 923 555-10-20",
      contactEmail: "anna.petrowa@example.com",
      notes: "Демо-лид для отображения CRM-блока в кабинете.",
      sourceType: "demo-seed",
      sourceId: demoProperty.id
    });
    changed = true;
  }

  if(db.notifications.length === 0){
    makeNotification(db, {
      type: "sms",
      recipient: "+7 923 555-10-20",
      owner: demoProperty.owner,
      channel: "viewing",
      relatedType: "demo-seed",
      relatedId: demoProperty.id,
      message: "Подтверждение показа на 26.03.2026 15:00 отправлено клиенту."
    });
    makeNotification(db, {
      type: "push",
      recipient: demoProperty.owner,
      owner: demoProperty.owner,
      channel: "crm",
      relatedType: "demo-seed",
      relatedId: demoProperty.id,
      message: "В CRM появился новый лид по объекту \"" + demoProperty.title + "\"."
    });
    changed = true;
  }

  if(db.messages.length === 0){
    db.messages.push({
      id: nextMessageId(db),
      name: "Ирина Смирнова",
      email: "irina.smirnova@example.com",
      message: "Подскажите, какие документы нужны для бронирования объекта?",
      createdAt: "2026-03-23T03:40:00.000Z"
    });
    changed = true;
  }

  if(changed){
    writeDB(db);
  }
}

function mimeType(p){
  const ext = path.extname(p).toLowerCase();
  if(ext === ".html") return "text/html; charset=utf-8";
  if(ext === ".css") return "text/css; charset=utf-8";
  if(ext === ".js") return "application/javascript; charset=utf-8";
  if(ext === ".json") return "application/json; charset=utf-8";
  if(ext === ".png") return "image/png";
  if(ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  if(ext === ".svg") return "image/svg+xml";
  return "application/octet-stream";
}

function sendStatic(res, filePath){
  if(!fs.existsSync(filePath)){
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  const stat = fs.statSync(filePath);
  res.writeHead(200, {
    "Content-Type": mimeType(filePath),
    "Content-Length": stat.size
  });
  fs.createReadStream(filePath).pipe(res);
}

function routeKey(req){
  const parsed = url.parse(req.url, true);
  return { pathname: parsed.pathname, query: parsed.query };
}

ensureSystemUsers();
seedPropertiesIfEmpty();
seedDemoIntegrations();

const server = http.createServer(async (req, res) => {
  try{
    const { pathname, query } = routeKey(req);

    // SPA hash маршруты: отдаём index.html для корня и html запросов
    if(pathname === "/" || pathname === "/index.html"){
      sendStatic(res, path.join(ROOT, "index.html"));
      return;
    }

    // API
    if(pathname.startsWith("/api/")){
      const session = getSessionFromReq(req);

      // Обратная связь (без авторизации)
      if(pathname === "/api/feedback" && req.method === "POST"){
        if(!session){
          jsonResponse(res, 401, { ok:false, message:"Сначала авторизуйтесь" });
          return;
        }
        const body = await parseBody(req);
        const name = sanitizeText(body.name, 120);
        const emailRaw = String(body.email || "").trim();
        const message = sanitizeText(body.message, 2500);
        if(!name || name.length < 2){
          jsonResponse(res, 400, { ok:false, message:"Укажите имя" });
          return;
        }
        if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailRaw)){
          jsonResponse(res, 400, { ok:false, message:"Некорректный email" });
          return;
        }
        if(!message || message.length < 5){
          jsonResponse(res, 400, { ok:false, message:"Сообщение слишком короткое" });
          return;
        }
        const db = readDB();
        if(!Array.isArray(db.messages)) db.messages = [];
        const messageId = nextMessageId(db);
        db.messages.push({
          id: messageId,
          name,
          email: sanitizeText(emailRaw, 120),
          message,
          createdAt: new Date().toISOString()
        });
        makeCrmLead(db, {
          title: "Обращение с формы обратной связи",
          channel: "feedback",
          stage: "new",
          owner: "admin",
          contactName: name,
          contactEmail: emailRaw,
          notes: message,
          sourceType: "feedback",
          sourceId: messageId
        });
        makeNotification(db, {
          type: "push",
          recipient: "admin",
          owner: "admin",
          channel: "feedback",
          relatedType: "feedback",
          relatedId: messageId,
          message: "Новое обращение от " + name + " (" + sanitizeText(emailRaw, 120) + ")"
        });
        writeDB(db);
        jsonResponse(res, 200, { ok:true, message:"Сообщение отправлено" });
        return;
      }

      // Публичный каталог (для гостей/клиентов): /api/properties/public?type=&rooms=&priceMax=&q=
      if(pathname === "/api/properties/public" && req.method === "GET"){
        const db = readDB();
        const type = String(query.type || "").trim();
        const rooms = query.rooms === undefined ? null : Number(query.rooms);
        const priceMax = query.priceMax === undefined ? null : Number(query.priceMax);
        const q = String(query.q || "").trim().toLowerCase();
        const allowedTypes = new Set(["Квартира","Дом","Комната","Коммерция"]);

        let list = db.properties.slice();
        if(type && allowedTypes.has(type)) list = list.filter(p => p.type === type);
        if(Number.isFinite(rooms)) list = list.filter(p => Number(p.rooms) === rooms);
        if(Number.isFinite(priceMax)) list = list.filter(p => Number(p.price) <= priceMax);
        if(q){
          list = list.filter(p => (
            String(p.title || "").toLowerCase().includes(q) ||
            String(p.address || "").toLowerCase().includes(q) ||
            String(p.description || "").toLowerCase().includes(q)
          ));
        }
        const compact = list.map(p => ({
          id: p.id,
          title: p.title,
          type: p.type,
          address: p.address,
          rooms: p.rooms,
          area: p.area,
          price: p.price,
          description: p.description,
          images: Array.isArray(p.images) ? p.images : [],
          owner: p.owner
        }));
        jsonResponse(res, 200, { ok:true, properties: compact });
        return;
      }

      // Заявка на просмотр (гость/клиент)
      if(pathname === "/api/viewings" && req.method === "POST"){
        const s = mustAuth(req, res);
        if(!s) return;
        const body = await parseBody(req);
        const db = readDB();
        const propertyId = Number(body.propertyId);
        const name = sanitizeText(body.name, 120);
        const phone = sanitizeText(body.phone, 40);
        const preferredDate = sanitizeText(body.preferredDate, 40);
        const comment = sanitizeText(body.comment, 500);
        const prop = db.properties.find(p => Number(p.id) === propertyId);
        if(!Number.isFinite(propertyId) || !prop){
          jsonResponse(res, 400, { ok:false, message: "Некорректный объект" }); return;
        }
        if(!name || name.length < 2){
          jsonResponse(res, 400, { ok:false, message: "Укажите имя" }); return;
        }
        if(!phone || phone.length < 6){
          jsonResponse(res, 400, { ok:false, message: "Укажите телефон" }); return;
        }
        if(!Array.isArray(db.viewings)) db.viewings = [];
        const viewing = {
          id: nextViewingId(db),
          propertyId,
          propertyTitle: prop.title,
          owner: prop.owner,
          requester: name,
          phone,
          preferredDate,
          comment,
          status: "new",
          createdAt: new Date().toISOString()
        };
        db.viewings.push(viewing);
        makeCalendarEvent(db, {
          title: "Просмотр: " + prop.title,
          startAt: parsePreferredDate(preferredDate) || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
          endAt: "",
          location: prop.address,
          owner: prop.owner,
          attendee: name,
          source: "viewing",
          status: "scheduled"
        });
        makeCrmLead(db, {
          title: "Лид по просмотру: " + prop.title,
          channel: "viewing",
          stage: "scheduled",
          owner: prop.owner,
          contactName: name,
          contactPhone: phone,
          notes: comment || preferredDate || "Заявка на просмотр с сайта",
          sourceType: "viewing",
          sourceId: viewing.id
        });
        makeNotification(db, {
          type: "sms",
          recipient: phone,
          owner: prop.owner,
          channel: "viewing",
          relatedType: "viewing",
          relatedId: viewing.id,
          message: "Заявка на просмотр принята по объекту \"" + prop.title + "\"."
        });
        makeNotification(db, {
          type: "push",
          recipient: prop.owner,
          owner: prop.owner,
          channel: "viewing",
          relatedType: "viewing",
          relatedId: viewing.id,
          message: "Новая заявка на просмотр: " + name + ", " + phone
        });
        writeDB(db);
        jsonResponse(res, 201, { ok:true, message:"Заявка на просмотр отправлена" });
        return;
      }

      // Auth: registration does not require auth
      if(pathname === "/api/auth/register" && req.method === "POST"){
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if(username.length < 3 || username.length > 24){
          jsonResponse(res, 400, { ok:false, message:"Логин должен быть от 3 до 24 символов" }); return;
        }
        if(!/^[a-zA-Z0-9_]+$/.test(username)){
          jsonResponse(res, 400, { ok:false, message:"Логин допускает только латиницу/цифры/подчеркивание" }); return;
        }
        if(password.length < 6){
          jsonResponse(res, 400, { ok:false, message:"Пароль должен быть минимум 6 символов" }); return;
        }

        const db = readDB();
        if(db.users.some(u => u.username === username)){
          jsonResponse(res, 409, { ok:false, message:"Пользователь с таким логином уже существует" }); return;
        }

        const salt = crypto.randomBytes(16).toString("hex");
        const roleRaw = String(body.role || "client").trim().toLowerCase();
        const role = (roleRaw === "agent") ? "agent" : "client";
        db.users.push({
          id: nextUserId(db),
          username,
          salt,
          passwordHash: hashPassword(password, salt),
          createdAt: new Date().toISOString(),
          role
        });
        writeDB(db);
        jsonResponse(res, 200, { ok:true, message:"Регистрация прошла успешно" });
        return;
      }

      if(pathname === "/api/auth/login" && req.method === "POST"){
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        const db = readDB();
        const user = db.users.find(u => u.username === username);
        if(!user) { jsonResponse(res, 401, { ok:false, message:"Неверный логин или пароль" }); return; }

        const expected = hashPassword(password, user.salt);
        if(expected !== user.passwordHash){
          jsonResponse(res, 401, { ok:false, message:"Неверный логин или пароль" }); return;
        }

        const token = crypto.randomBytes(24).toString("hex");
        const csrfToken = crypto.randomBytes(16).toString("hex");
        sessions.set(token, {
          username,
          role: user.role || "client",
          csrfToken,
          exp: Date.now() + 1000*60*60
        });
        jsonResponse(res, 200, { ok:true, token, csrfToken, role: user.role || "client" });
        return;
      }

      if(pathname === "/api/auth/me" && req.method === "GET"){
        const session0 = getSessionFromReq(req);
        if(!session0){
          jsonResponse(res, 401, { ok:false, message:"Unauthorized" });
          return;
        }
        // Для /me CSRF не требуем, но если прислали — сверим.
        const csrf = req.headers["x-csrf-token"] || "";
        if(csrf && csrf !== session0.csrfToken){
          jsonResponse(res, 403, { ok:false, message:"CSRF token mismatch" });
          return;
        }
        jsonResponse(res, 200, {
          ok:true,
          username: session0.username,
          role: session0.role || "client",
          csrfToken: session0.csrfToken
        });
        return;
      }

      // Properties CRUD (requires auth + CSRF on mutations)
      if(pathname === "/api/properties" && req.method === "GET"){
        if(!session){
          jsonResponse(res, 401, { ok:false, message:"Unauthorized" }); return;
        }
        // Читаем только "ваши" объявления.
        const db = readDB();
        const mine = (session.role === "admin")
          ? db.properties
          : db.properties.filter(p => p.owner === session.username);
        jsonResponse(res, 200, { ok:true, properties: mine, role: session.role || "client" });
        return;
      }

      if(pathname === "/api/properties" && req.method === "POST"){
        const s = mustAuth(req, res);
        if(!s) return;
        const body = await parseBody(req);
        const db = readDB();

        const title = sanitizeText(body.title, 80);
        const address = sanitizeText(body.address, 120);
        const type = sanitizeText(body.type, 20);
        const description = sanitizeText(body.description, 2000);
        const rooms = Number(body.rooms);
        const area = Number(body.area);
        const price = Number(body.price);

        if(!title || title.length < 3){ jsonResponse(res, 400, { ok:false, message:"Некорректный заголовок" }); return; }
        if(!address || address.length < 5){ jsonResponse(res, 400, { ok:false, message:"Некорректный адрес" }); return; }
        if(!Number.isFinite(rooms) || rooms < 0){ jsonResponse(res, 400, { ok:false, message:"Некорректное число комнат" }); return; }
        if(!Number.isFinite(area) || area <= 0){ jsonResponse(res, 400, { ok:false, message:"Некорректная площадь" }); return; }
        if(!Number.isFinite(price) || price <= 0){ jsonResponse(res, 400, { ok:false, message:"Некорректная цена" }); return; }

        const allowedTypes = new Set(["Квартира","Дом","Комната","Коммерция"]);
        if(!allowedTypes.has(type)){ jsonResponse(res, 400, { ok:false, message:"Некорректный тип" }); return; }

        const images = normalizeImages(body.images);

        const nextId = (db.properties.reduce((m, p) => Math.max(m, p.id || 0), 0) + 1);
        const property = {
          id: nextId,
          owner: s.username,
          createdAt: new Date().toISOString(),
          updatedAt: null,
          title,
          address,
          type,
          rooms,
          area,
          price,
          description,
          images
        };
        db.properties.unshift(property);
        writeDB(db);
        jsonResponse(res, 201, { ok:true, property });
        return;
      }

      // /api/properties/:id
      const propIdMatch = pathname.match(/^\/api\/properties\/(\d+)$/);
      if(propIdMatch){
        const id = Number(propIdMatch[1]);
        const s = mustAuth(req, res);
        if(!s) return;
        const db = readDB();
        const idx = db.properties.findIndex(p => (
          Number(p.id) === id && (s.role === "admin" || p.owner === s.username)
        ));
        if(idx === -1){
          jsonResponse(res, 404, { ok:false, message:"Объявление не найдено" });
          return;
        }

        if(req.method === "PUT"){
          const body = await parseBody(req);
          const title = sanitizeText(body.title, 80);
          const address = sanitizeText(body.address, 120);
          const type = sanitizeText(body.type, 20);
          const description = sanitizeText(body.description, 2000);
          const rooms = Number(body.rooms);
          const area = Number(body.area);
          const price = Number(body.price);

          const allowedTypes = new Set(["Квартира","Дом","Комната","Коммерция"]);
          if(!allowedTypes.has(type)){ jsonResponse(res, 400, { ok:false, message:"Некорректный тип" }); return; }
          if(!title || title.length < 3){ jsonResponse(res, 400, { ok:false, message:"Некорректный заголовок" }); return; }
          if(!address || address.length < 5){ jsonResponse(res, 400, { ok:false, message:"Некорректный адрес" }); return; }
          if(!Number.isFinite(rooms) || rooms < 0){ jsonResponse(res, 400, { ok:false, message:"Некорректное число комнат" }); return; }
          if(!Number.isFinite(area) || area <= 0){ jsonResponse(res, 400, { ok:false, message:"Некорректная площадь" }); return; }
          if(!Number.isFinite(price) || price <= 0){ jsonResponse(res, 400, { ok:false, message:"Некорректная цена" }); return; }

          const images = body.images !== undefined
            ? normalizeImages(body.images)
            : (Array.isArray(db.properties[idx].images) ? db.properties[idx].images : []);

          const updated = {
            ...db.properties[idx],
            updatedAt: new Date().toISOString(),
            title,
            address,
            type,
            rooms,
            area,
            price,
            description,
            images
          };
          db.properties[idx] = updated;
          writeDB(db);
          jsonResponse(res, 200, { ok:true, property: updated });
          return;
        }

        if(req.method === "DELETE"){
          const removed = db.properties.splice(idx, 1)[0];
          writeDB(db);
          jsonResponse(res, 200, { ok:true, deleted: removed });
          return;
        }
      }

      // Админ/агент: просмотр заявок на показы
      if(pathname === "/api/viewings" && req.method === "GET"){
        if(!session){
          jsonResponse(res, 401, { ok:false, message:"Unauthorized" }); return;
        }
        const db = readDB();
        const list = (session.role === "admin")
          ? db.viewings
          : db.viewings.filter(v => v.owner === session.username);
        jsonResponse(res, 200, { ok:true, viewings: list });
        return;
      }

      // Админ: сообщения обратной связи
      if(pathname === "/api/integrations/summary" && req.method === "GET"){
        if(!session){
          jsonResponse(res, 401, { ok:false, message:"Unauthorized" }); return;
        }
        const db = readDB();
        const isAdmin = session.role === "admin";
        const byOwner = (item) => isAdmin || String(item.owner || "") === session.username;
        const notifications = db.notifications.filter(byOwner);
        const calendarEvents = db.calendarEvents.filter(byOwner);
        const crmLeads = db.crmLeads.filter(byOwner);
        const viewings = isAdmin
          ? db.viewings
          : db.viewings.filter(v => v.owner === session.username);
        jsonResponse(res, 200, {
          ok:true,
          viewings,
          notifications,
          calendarEvents,
          crmLeads
        });
        return;
      }

      if(pathname === "/api/admin/messages" && req.method === "GET"){
        if(!session || session.role !== "admin"){
          jsonResponse(res, 403, { ok:false, message:"Forbidden" }); return;
        }
        const db = readDB();
        jsonResponse(res, 200, { ok:true, messages: db.messages });
        return;
      }

      jsonResponse(res, 404, { ok:false, message:"API endpoint not found" });
      return;
    }

    // Статика для остальных файлов (на случай если добавишь CSS/JS отдельно)
    const safePath = path.normalize(decodeURIComponent(pathname)).replace(/^(\.\.[\/\\])+/, "");
    const full = path.join(ROOT, safePath);
    if(full.startsWith(ROOT) && fs.existsSync(full) && fs.statSync(full).isFile()){
      sendStatic(res, full);
      return;
    }

    // Fallback для SPA
    sendStatic(res, path.join(ROOT, "index.html"));
  }catch(err){
    jsonResponse(res, 500, { ok:false, message: String(err.message || err) });
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log("Server started: http://localhost:" + PORT);
});

