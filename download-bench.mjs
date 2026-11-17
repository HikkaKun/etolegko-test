#!/usr/bin/env node
/**
 * download-bench.mjs — последовательный замер скорости скачивания URL.
 *
 * Скрипт N раз подряд (без параллелизма) скачивает один и тот же ресурс,
 * каждый раз дожидаясь полного тела ответа, и считает:
 *   - время каждого запроса целиком (соединение + заголовки + тело);
 *   - среднее, медиану, минимум и максимум по времени;
 *   - суммарный объём скачанных данных;
 *   - скорость как «суммарный объём / общее время».
 *
 * Зависимостей нет — только стандартная библиотека Node.js.
 *
 * Безопасность: по умолчанию запрещены loopback, частные, link-local и
 * прочие непубличные адреса (защита от SSRF и DNS rebinding), редиректы
 * ограничены и проверяются на каждом шаге, тело не буферизуется в памяти,
 * на размер ответа и время запроса действуют лимиты. Подробности — в README.
 */

import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import process from 'node:process';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

const VERSION = '1.0.0';
const MIB = 1024 * 1024;
const MAX_REQUESTS = 1000;
const MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const MAX_BYTES_LIMIT = 8 * 1024 * MIB;
const MAX_REDIRECTS_LIMIT = 20;
const MAX_URL_LENGTH = 8192;
const USER_AGENT = `download-bench/${VERSION} (Node.js ${process.version})`;

const DEFAULTS = Object.freeze({
  requests: 10,
  timeoutMs: 60_000,
  maxBytes: 512 * MIB,
  maxRedirects: 5,
});

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// ---------------------------------------------------------------------------
// Ошибки
// ---------------------------------------------------------------------------

export class BenchError extends Error {
  /**
   * @param {string} code машинный код ошибки
   * @param {string} message сообщение для человека
   * @param {{cause?: unknown, details?: unknown}} [options]
   */
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'BenchError';
    this.code = code;
    this.details = options.details;
  }
}

export class UsageError extends BenchError {
  constructor(message, options = {}) {
    super('USAGE', message, options);
    this.name = 'UsageError';
  }
}

// ---------------------------------------------------------------------------
// Форматирование и защита вывода
// ---------------------------------------------------------------------------

/**
 * Убирает управляющие символы из строк, полученных от сервера или из URL,
 * чтобы они не могли вставить ANSI-последовательности в терминал.
 */
export function sanitizeForTerminal(value, maxLength = 500) {
  let text = String(value ?? '');
  if (text.length > maxLength) text = `${text.slice(0, maxLength)}…`;
  return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, (char) => {
    const hex = char.codePointAt(0).toString(16).padStart(2, '0');
    return `\\x${hex}`;
  });
}

function formatInteger(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < MIB) return `${(bytes / 1024).toFixed(1)} КиБ`;
  return `${(bytes / MIB).toFixed(2)} МиБ`;
}

function formatMs(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} с`;
  return `${ms.toFixed(1)} мс`;
}

function formatSpeed(bytes, ms) {
  if (!(ms > 0)) return '—';
  const mibPerSecond = bytes / MIB / (ms / 1000);
  return `${mibPerSecond.toFixed(2)} МиБ/с`;
}

function round(value, digits = 3) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

// ---------------------------------------------------------------------------
// Разбор аргументов командной строки
// ---------------------------------------------------------------------------

/**
 * @param {string[]} argv аргументы без node и имени скрипта
 * @returns {object} разобранные и проверенные опции
 */
export function parseArgs(argv) {
  const options = {
    target: null,
    requests: DEFAULTS.requests,
    timeoutMs: DEFAULTS.timeoutMs,
    maxBytes: DEFAULTS.maxBytes,
    maxRedirects: DEFAULTS.maxRedirects,
    allowPrivate: false,
    json: false,
    help: false,
  };

  const positionals = [];
  let endOfFlags = false;

  const ensureNoInlineValue = (flag, inlineValue) => {
    if (inlineValue !== undefined) {
      throw new UsageError(`Флаг ${flag} не принимает значение`);
    }
  };

  for (let i = 0; i < argv.length; i += 1) {
    const rawArg = argv[i];

    if (endOfFlags) {
      positionals.push(rawArg);
      continue;
    }
    if (rawArg === '--') {
      endOfFlags = true;
      continue;
    }
    if (!rawArg.startsWith('-') || rawArg === '-') {
      positionals.push(rawArg);
      continue;
    }

    let flag = rawArg;
    let inlineValue;
    if (flag.startsWith('--')) {
      const equalsIndex = flag.indexOf('=');
      if (equalsIndex !== -1) {
        inlineValue = flag.slice(equalsIndex + 1);
        flag = flag.slice(0, equalsIndex);
      }
    }

    const takeValue = () => {
      if (inlineValue !== undefined) return inlineValue;
      if (i + 1 >= argv.length) {
        throw new UsageError(`Флаг ${flag} требует значение`);
      }
      i += 1;
      return argv[i];
    };

    switch (flag) {
      case '-h':
      case '--help':
        ensureNoInlineValue(flag, inlineValue);
        options.help = true;
        break;
      case '--json':
        ensureNoInlineValue(flag, inlineValue);
        options.json = true;
        break;
      case '--allow-private':
        ensureNoInlineValue(flag, inlineValue);
        options.allowPrivate = true;
        break;
      case '-n':
      case '--requests':
        options.requests = parseIntegerFlag('--requests', takeValue(), {
          min: 1,
          max: MAX_REQUESTS,
        });
        break;
      case '-t':
      case '--timeout':
        options.timeoutMs = parseIntegerFlag('--timeout', takeValue(), {
          min: 1,
          max: MAX_TIMEOUT_MS,
        });
        break;
      case '--max-bytes':
        options.maxBytes = parseIntegerFlag('--max-bytes', takeValue(), {
          min: 1,
          max: MAX_BYTES_LIMIT,
        });
        break;
      case '--max-redirects':
        options.maxRedirects = parseIntegerFlag('--max-redirects', takeValue(), {
          min: 0,
          max: MAX_REDIRECTS_LIMIT,
        });
        break;
      default:
        throw new UsageError(`Неизвестный флаг: ${flag}`);
    }
  }

  if (options.help) return options;

  if (positionals.length === 0) {
    throw new UsageError('Не указан URL. Пример: node download-bench.mjs https://example.com/image.jpg');
  }
  if (positionals.length > 1) {
    throw new UsageError('Ожидается ровно один URL, лишние аргументы не поддерживаются');
  }

  options.target = parseTarget(positionals[0]);
  return options;
}

function parseIntegerFlag(flag, raw, { min, max }) {
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    throw new UsageError(`Флаг ${flag}: ожидается целое число, получено «${sanitizeForTerminal(raw, 50)}»`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new UsageError(`Флаг ${flag}: допустимый диапазон ${min}..${max}`);
  }
  return value;
}

/**
 * Проверяет URL и возвращает нормализованный объект URL.
 * @param {string} raw
 * @returns {URL}
 */
export function parseTarget(raw) {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new UsageError('Пустой URL');
  }
  if (raw.length > MAX_URL_LENGTH) {
    throw new UsageError(`URL длиннее ${MAX_URL_LENGTH} символов`);
  }
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    throw new UsageError('URL содержит управляющие символы');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new UsageError(`Не удалось разобрать URL: ${sanitizeForTerminal(raw, 200)}`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new UsageError(`Поддерживаются только http:// и https://, получено: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new UsageError('URL с логином/паролем не поддерживается: учётные данные могут утечь в логи');
  }
  if (url.port === '0') {
    throw new UsageError('Порт 0 недопустим');
  }
  if (!url.hostname) {
    throw new UsageError('В URL отсутствует хост');
  }

  // Фрагмент не отправляется на сервер, поэтому убираем его из всех отчётов.
  url.hash = '';
  return url;
}

// ---------------------------------------------------------------------------
// Проверка адресов (защита от SSRF / DNS rebinding)
// ---------------------------------------------------------------------------

function ipv4ToInt(address) {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function formatIPv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');
}

function ipv4Mask(prefix) {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

const BLOCKED_IPV4_RANGES = [
  ['0.0.0.0', 8, 'сеть 0.0.0.0/8'],
  ['10.0.0.0', 8, 'частная сеть 10.0.0.0/8'],
  ['100.64.0.0', 10, 'CGNAT 100.64.0.0/10'],
  ['127.0.0.0', 8, 'loopback 127.0.0.0/8'],
  ['169.254.0.0', 16, 'link-local 169.254.0.0/16 (в т.ч. cloud metadata)'],
  ['172.16.0.0', 12, 'частная сеть 172.16.0.0/12'],
  ['192.0.0.0', 24, 'IETF protocol assignments 192.0.0.0/24'],
  ['192.0.2.0', 24, 'документационная сеть 192.0.2.0/24'],
  ['192.88.99.0', 24, '6to4 relay anycast 192.88.99.0/24'],
  ['192.168.0.0', 16, 'частная сеть 192.168.0.0/16'],
  ['198.18.0.0', 15, 'бенчмарк-сеть 198.18.0.0/15'],
  ['198.51.100.0', 24, 'документационная сеть 198.51.100.0/24'],
  ['203.0.113.0', 24, 'документационная сеть 203.0.113.0/24'],
  ['224.0.0.0', 4, 'multicast 224.0.0.0/4'],
  ['240.0.0.0', 4, 'зарезервированная сеть 240.0.0.0/4'],
].map(([base, prefix, reason]) => ({
  base: ipv4ToInt(base),
  mask: ipv4Mask(prefix),
  reason,
}));

function blockedIPv4Reason(value) {
  for (const range of BLOCKED_IPV4_RANGES) {
    if ((value & range.mask) === (range.base & range.mask)) return range.reason;
  }
  return null;
}

function parseIPv6Words(address) {
  let text = address;
  const zoneIndex = text.indexOf('%');
  if (zoneIndex !== -1) text = text.slice(0, zoneIndex);

  const lastColon = text.lastIndexOf(':');
  if (lastColon === -1) return null;

  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const embedded = ipv4ToInt(tail);
    if (embedded === null) return null;
    const high = (embedded >>> 16).toString(16);
    const low = (embedded & 0xffff).toString(16);
    text = `${text.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  let groups;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array(missing).fill('0'), ...rest];
  }

  if (groups.length !== 8) return null;
  const words = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    words.push(parseInt(group, 16));
  }
  return words;
}

function blockedIPv6Reason(address) {
  const words = parseIPv6Words(address);
  if (!words) return 'некорректный IPv6-адрес';

  const [w0, w1, w2, w3, w4, w5, w6, w7] = words;
  const firstFiveZero = w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0;

  // ::ffff:0:0/96 — IPv4-mapped.
  if (firstFiveZero && w5 === 0xffff) {
    const value = ((w6 << 16) | w7) >>> 0;
    const reason = blockedIPv4Reason(value);
    return reason ? `IPv4-mapped ${formatIPv4(value)}: ${reason}` : null;
  }

  // ::/96 — IPv4-compatible, устаревший, но всё ещё может привести к IPv4.
  if (firstFiveZero && w5 === 0) {
    if (w6 === 0 && w7 === 0) return 'неопределённый адрес ::';
    if (w6 === 0 && w7 === 1) return 'loopback ::1';
    const value = ((w6 << 16) | w7) >>> 0;
    const reason = blockedIPv4Reason(value);
    return reason ? `IPv4-compatible ${formatIPv4(value)}: ${reason}` : null;
  }

  // Разрешаем только глобальный unicast 2000::/3. Это отсекает ::/128,
  // ULA fc00::/7, link-local fe80::/10, multicast ff00::/8, NAT64 64:ff9b::/96
  // и прочие зарезервированные диапазоны.
  if ((w0 & 0xe000) !== 0x2000) {
    return 'адрес вне глобального unicast 2000::/3 (loopback, ULA, link-local, multicast или зарезервированный)';
  }

  if (w0 === 0x2001 && w1 === 0x0db8) return 'документационная сеть 2001:db8::/32';
  if (w0 === 0x2001 && w1 === 0x0000) return 'Teredo 2001::/32';
  if (w0 === 0x2001 && w1 === 0x0002 && w2 === 0x0000) return 'бенчмарк-сеть 2001:2::/48';
  if (w0 === 0x2001 && (w1 & 0xfff0) === 0x0010) return 'ORCHID 2001:10::/28';
  if (w0 === 0x2001 && (w1 & 0xfff0) === 0x0020) return 'ORCHIDv2 2001:20::/28';
  if (w0 === 0x2001 && w1 === 0x0004 && w2 === 0x0112) return 'AS112 2001:4:112::/48';
  if (w0 === 0x3fff && (w1 & 0xf000) === 0x0000) return 'документационная сеть 3fff::/20';

  // 6to4 2002::/16 содержит встроенный IPv4 — проверяем его отдельно.
  if (w0 === 0x2002) {
    const value = ((w1 << 16) | w2) >>> 0;
    const reason = blockedIPv4Reason(value);
    return reason ? `6to4 ${formatIPv4(value)}: ${reason}` : null;
  }

  return null;
}

/**
 * Возвращает причину, по которой адрес считается непубличным, либо null.
 * @param {string} address IPv4 или IPv6 в каноническом виде
 * @returns {string|null}
 */
export function blockedAddressReason(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const value = ipv4ToInt(address);
    return value === null ? 'некорректный IPv4-адрес' : blockedIPv4Reason(value);
  }
  if (family === 6) return blockedIPv6Reason(address);
  return 'не IP-адрес';
}

/**
 * @param {string} address
 * @returns {boolean} true, если адрес публичный и глобально маршрутизируемый
 */
export function isPublicAddress(address) {
  return net.isIP(address) !== 0 && blockedAddressReason(address) === null;
}

/**
 * Не даёт подключиться к IP-литералу из приватного диапазона.
 * Для доменных имён настоящая проверка выполняется в lookup при подключении.
 */
export function assertHostAllowed(hostname, allowPrivate = false) {
  if (allowPrivate) return;
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (net.isIP(bare) === 0) return;
  const reason = blockedAddressReason(bare);
  if (reason) {
    throw new BenchError(
      'BLOCKED_ADDRESS',
      `Запрос к адресу ${bare} запрещён: ${reason}. Для осознанного локального теста используйте --allow-private.`,
    );
  }
}

/**
 * Создаёт lookup-функцию для net.connect: она проверяет КАЖДЫЙ полученный
 * из DNS адрес и отдаёт сокету только публичные. Проверка происходит в момент
 * подключения, поэтому подмена DNS между проверкой и соединением (DNS
 * rebinding) не срабатывает.
 */
export function createGuardedLookup() {
  return function guardedLookup(hostname, options, callback) {
    const wantsAll = Boolean(options?.all);
    try {
      dns.lookup(hostname, { ...(options ?? {}), all: true }, (error, addresses) => {
        if (error) {
          callback(error);
          return;
        }
        const list = Array.isArray(addresses) ? addresses : [];
        const allowed = list.filter((entry) => isPublicAddress(entry.address));
        if (allowed.length === 0) {
          const shown = list.length > 0 ? list.map((entry) => entry.address).join(', ') : 'нет адресов';
          const reason = list.length > 0 ? blockedAddressReason(list[0].address) : 'DNS не вернул адресов';
          callback(
            new BenchError(
              'BLOCKED_ADDRESS',
              `Хост ${sanitizeForTerminal(hostname, 255)} разрешается в непубличные адреса (${sanitizeForTerminal(shown, 255)}): ${reason}. Запрос заблокирован для защиты от SSRF.`,
            ),
          );
          return;
        }
        if (wantsAll) {
          callback(null, allowed);
        } else {
          callback(null, allowed[0].address, allowed[0].family);
        }
      });
    } catch (error) {
      callback(error);
    }
  };
}

// ---------------------------------------------------------------------------
// HTTP-слой
// ---------------------------------------------------------------------------

function firstHeader(headers, name) {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function parseContentLength(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number(trimmed);
  return Number.isSafeInteger(value) ? value : null;
}

function normalizeContentEncoding(raw) {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value ? String(value).toLowerCase() : null;
}

function abortReason(signal) {
  if (!signal) return new BenchError('ABORTED', 'Операция прервана');
  const reason = signal.reason;
  if (reason instanceof BenchError) return reason;
  if (reason instanceof Error) return new BenchError('ABORTED', 'Операция прервана', { cause: reason });
  return new BenchError('ABORTED', 'Операция прервана');
}

function timeoutError(timeoutMs) {
  return new BenchError(
    'TIMEOUT',
    `Превышен таймаут ${formatMs(timeoutMs)}: запрос не завершён целиком (включая тело ответа).`,
  );
}

function toBenchError(error, signal) {
  if (error instanceof BenchError) return error;
  if (signal?.aborted) return abortReason(signal);
  if (error?.name === 'AbortError') {
    return new BenchError('ABORTED', 'Операция прервана', { cause: error });
  }

  const code = error?.code;
  if (code === 'EBLOCKED') {
    return new BenchError('BLOCKED_ADDRESS', error.message, { cause: error });
  }
  if (['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'EAI_NODATA', 'EAI_NONAME', 'ESERVFAIL', 'EREFUSED'].includes(code)) {
    return new BenchError('DNS', `Не удалось разрешить имя: ${error.message}`, { cause: error });
  }
  if (
    typeof code === 'string' &&
    /^(CERT_|ERR_TLS_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_|HOSTNAME_MISMATCH|ERR_SSL_)/.test(code)
  ) {
    return new BenchError('TLS', `Ошибка TLS: ${error.message}`, { cause: error });
  }
  return new BenchError('NETWORK', `Сетевая ошибка: ${error?.message ?? String(error)}`, { cause: error });
}

/**
 * Отправляет один HTTP-запрос и резолвится, как только пришли заголовки ответа.
 * Таймаут и отмена управляются снаружи через signal.
 */
function openRequest(url, { signal, lookup, agent }) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    let settled = false;

    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(toBenchError(error, signal));
    };

    let request;
    try {
      request = transport.request(url, {
        method: 'GET',
        headers: {
          'user-agent': USER_AGENT,
          accept: '*/*',
          // Просим не сжимать ответ, чтобы считать реальный объём полезной
          // нагрузки. Если сервер всё равно сожмёт, посчитаются байты на
          // проводе (см. примечание в отчёте).
          'accept-encoding': 'identity',
        },
        lookup,
        agent,
        signal,
      });
    } catch (error) {
      fail(error);
      return;
    }

    request.on('error', fail);
    request.on('response', (response) => {
      if (settled) {
        response.destroy();
        return;
      }
      settled = true;
      // Ошибки тела обрабатывает readBody; этот обработчик нужен, чтобы
      // поздние события не роняли процесс «unhandled error».
      response.on('error', () => {});
      resolve({ request, response });
    });

    request.end();
  });
}

/**
 * Читает тело ответа, считая байты и не сохраняя его в памяти.
 * @returns {Promise<number>} число полученных байт тела
 */
function readBody(response, { maxBytes, contentLength, signal }) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    let settled = false;

    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', onAbort);
      callback(value);
    };

    const onAbort = () => finish(reject, abortReason(signal));

    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });

    if (contentLength !== null && contentLength > maxBytes) {
      finish(
        reject,
        new BenchError(
          'TOO_LARGE',
          `Content-Length ${formatInteger(contentLength)} байт превышает лимит ${formatInteger(maxBytes)} байт.`,
          { details: { contentLength, maxBytes } },
        ),
      );
      response.destroy();
      return;
    }

    response.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        finish(
          reject,
          new BenchError(
            'TOO_LARGE',
            `Тело ответа превысило лимит ${formatInteger(maxBytes)} байт (получено уже ${formatInteger(bytes)}).`,
            { details: { maxBytes, bytes } },
          ),
        );
        response.destroy();
      }
    });

    response.on('end', () => {
      if (!response.complete) {
        finish(reject, new BenchError('TRUNCATED', 'Соединение закрылось раньше конца тела ответа.'));
        return;
      }
      if (contentLength !== null && bytes < contentLength) {
        finish(
          reject,
          new BenchError(
            'TRUNCATED',
            `Получено ${formatInteger(bytes)} из ${formatInteger(contentLength)} байт: ответ оборван.`,
            { details: { bytes, contentLength } },
          ),
        );
        return;
      }
      finish(resolve, bytes);
    });

    response.on('aborted', () => {
      finish(reject, new BenchError('TRUNCATED', 'Загрузка тела ответа прервана.'));
    });

    response.on('error', (error) => {
      finish(reject, toBenchError(error, signal));
    });

    response.on('close', () => {
      if (!settled) {
        finish(
          reject,
          signal.aborted
            ? abortReason(signal)
            : new BenchError('TRUNCATED', 'Соединение закрыто до завершения ответа.'),
        );
      }
    });
  });
}

/**
 * Скачивает URL один раз: обрабатывает редиректы, проверяет статус и
 * прочитывает тело до конца.
 */
async function downloadOnce(target, options, parentSignal) {
  const startedAt = performance.now();
  const deadline = startedAt + options.timeoutMs;
  const visited = new Set();
  let current = target;
  let redirects = 0;

  for (;;) {
    if (parentSignal?.aborted) throw abortReason(parentSignal);

    if (visited.has(current.href)) {
      throw new BenchError('REDIRECT_LOOP', `Обнаружен цикл редиректов на ${current.href}.`);
    }
    visited.add(current.href);
    assertHostAllowed(current.hostname, options.allowPrivate);

    const remaining = deadline - performance.now();
    if (remaining <= 0) throw timeoutError(options.timeoutMs);

    const controller = new AbortController();
    const onParentAbort = () => controller.abort(abortReason(parentSignal));
    parentSignal?.addEventListener('abort', onParentAbort, { once: true });
    const timer = setTimeout(
      () => controller.abort(timeoutError(options.timeoutMs)),
      Math.max(1, Math.floor(remaining)),
    );

    let request = null;
    try {
      const agent = current.protocol === 'https:' ? options.agents?.https : options.agents?.http;
      request = await openRequest(current, {
        signal: controller.signal,
        lookup: options.lookup,
        agent,
      });
      const { response } = request;
      const status = response.statusCode ?? 0;
      const headers = response.headers;
      const contentLength = parseContentLength(firstHeader(headers, 'content-length'));
      const contentEncoding = normalizeContentEncoding(firstHeader(headers, 'content-encoding'));

      if (REDIRECT_STATUSES.has(status)) {
        const location = firstHeader(headers, 'location');
        if (!location) {
          response.destroy();
          throw new BenchError('REDIRECT_NO_LOCATION', `Сервер ответил HTTP ${status} без заголовка Location.`);
        }
        if (redirects >= options.maxRedirects) {
          response.destroy();
          throw new BenchError(
            'REDIRECT_LIMIT',
            `Превышен лимит редиректов (${options.maxRedirects}). Последний адрес: ${current.href}`,
          );
        }

        let next;
        try {
          next = new URL(location, current);
        } catch {
          response.destroy();
          throw new BenchError('REDIRECT_INVALID', `Некорректный заголовок Location: ${sanitizeForTerminal(location, 300)}`);
        }
        response.destroy();

        if (next.protocol !== 'http:' && next.protocol !== 'https:') {
          throw new BenchError('REDIRECT_PROTOCOL', `Редирект на неподдерживаемый протокол ${next.protocol}.`);
        }
        if (current.protocol === 'https:' && next.protocol === 'http:') {
          throw new BenchError('INSECURE_REDIRECT', 'Редирект с HTTPS на HTTP запрещён: возможна атака downgrade.');
        }
        if (!next.hostname || next.port === '0') {
          throw new BenchError('REDIRECT_INVALID', 'Редирект ведёт на некорректный хост или порт.');
        }
        if (next.href.length > MAX_URL_LENGTH) {
          throw new BenchError('REDIRECT_INVALID', `URL после редиректа длиннее ${MAX_URL_LENGTH} символов.`);
        }

        // Учётные данные из Location не переносим и не пересылаем.
        if (next.username || next.password) {
          next.username = '';
          next.password = '';
        }
        next.hash = '';

        current = next;
        redirects += 1;
        continue;
      }

      if (status < 200 || status >= 300) {
        response.destroy();
        const reason = sanitizeForTerminal(response.statusMessage ?? '');
        throw new BenchError(
          'HTTP_STATUS',
          `Сервер ответил HTTP ${status}${reason ? ` ${reason}` : ''}. Ожидался статус 2xx.`,
          { details: { status } },
        );
      }

      const bytes = await readBody(response, {
        maxBytes: options.maxBytes,
        contentLength,
        signal: controller.signal,
      });

      return {
        bytes,
        durationMs: performance.now() - startedAt,
        status,
        contentType: sanitizeForTerminal(firstHeader(headers, 'content-type') ?? '', 200),
        contentEncoding,
        finalUrl: current.href,
      };
    } catch (error) {
      throw toBenchError(error, controller.signal);
    } finally {
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', onParentAbort);
      // Если тело не дочитано (ошибка, редирект, лимит), закрываем сокет.
      // Успешно прочитанный ответ оставляем в keep-alive пуле агента.
      if (!request?.response?.complete) request?.request.destroy();
    }
  }
}

// ---------------------------------------------------------------------------
// Замер и отчёт
// ---------------------------------------------------------------------------

/**
 * @param {object} options результат parseArgs (+ lookup, agents, signal)
 * @returns {Promise<object>} машинно-читаемый отчёт
 */
export async function runBenchmark(options) {
  if (!(options.target instanceof URL)) {
    throw new TypeError('options.target должен быть объектом URL');
  }

  const agents = {
    http: new http.Agent({ keepAlive: true, maxSockets: 1 }),
    https: new https.Agent({ keepAlive: true, maxSockets: 1 }),
  };
  const runOptions = {
    ...options,
    agents,
    lookup: options.allowPrivate ? undefined : createGuardedLookup(),
  };

  const perRequest = [];
  const startedAt = performance.now();

  try {
    for (let index = 1; index <= options.requests; index += 1) {
      if (options.signal?.aborted) throw abortReason(options.signal);
      const result = await downloadOnce(options.target, runOptions, options.signal);
      perRequest.push({ index, ...result });
    }
  } finally {
    agents.http.destroy();
    agents.https.destroy();
  }

  const totalTimeMs = performance.now() - startedAt;
  const summary = summarize(perRequest, totalTimeMs);
  return buildReport(options, perRequest, summary);
}

export function summarize(perRequest, totalTimeMs) {
  const count = perRequest.length;
  const totalBytes = perRequest.reduce((sum, item) => sum + item.bytes, 0);
  const times = perRequest.map((item) => item.durationMs);
  const sorted = [...times].sort((a, b) => a - b);

  const avgRequestMs = count > 0 ? times.reduce((sum, value) => sum + value, 0) / count : 0;
  const medianRequestMs =
    count === 0
      ? 0
      : count % 2 === 1
        ? sorted[(count - 1) / 2]
        : (sorted[count / 2 - 1] + sorted[count / 2]) / 2;

  const seconds = totalTimeMs / 1000;
  const bytesPerSecond = seconds > 0 ? totalBytes / seconds : 0;

  return {
    totalBytes,
    totalTimeMs,
    avgRequestMs,
    medianRequestMs,
    minRequestMs: count > 0 ? sorted[0] : 0,
    maxRequestMs: count > 0 ? sorted[count - 1] : 0,
    mibPerSecond: bytesPerSecond / MIB,
    mbitPerSecond: (bytesPerSecond * 8) / 1_000_000,
  };
}

function buildReport(options, perRequest, summary) {
  const last = perRequest[perRequest.length - 1];
  return {
    ok: true,
    target: options.target.href,
    finalUrl: last.finalUrl,
    status: last.status,
    contentType: last.contentType || null,
    contentEncoding: last.contentEncoding,
    requests: options.requests,
    totalBytes: summary.totalBytes,
    totalTimeMs: round(summary.totalTimeMs),
    avgRequestMs: round(summary.avgRequestMs),
    medianRequestMs: round(summary.medianRequestMs),
    minRequestMs: round(summary.minRequestMs),
    maxRequestMs: round(summary.maxRequestMs),
    throughput: {
      mibPerSecond: round(summary.mibPerSecond, 6),
      mbitPerSecond: round(summary.mbitPerSecond, 6),
    },
    units: {
      bytes: 'байты',
      requestTime: 'миллисекунды',
      throughput: 'МиБ/с (1 МиБ = 1 048 576 байт)',
      throughputBits: 'Мбит/с (1 Мбит = 1 000 000 бит)',
    },
    perRequest: perRequest.map((item) => ({
      index: item.index,
      bytes: item.bytes,
      durationMs: round(item.durationMs),
    })),
  };
}

export function formatReport(report) {
  const lines = [];
  lines.push(`Цель:        ${sanitizeForTerminal(report.target)}`);
  if (report.finalUrl !== report.target) {
    lines.push(`Итоговый URL: ${sanitizeForTerminal(report.finalUrl)}`);
  }
  lines.push(`Запросов:    ${report.requests} (последовательно, каждый до полного конца тела)`);
  lines.push('');
  lines.push('   #  время          байт              скорость');
  lines.push('  ---  -------------  ----------------  ----------------');
  for (const item of report.perRequest) {
    const index = String(item.index).padStart(2);
    lines.push(
      `  ${index}  ${formatMs(item.durationMs).padEnd(13)}  ${formatBytes(item.bytes).padEnd(16)}  ${formatSpeed(item.bytes, item.durationMs)}`,
    );
  }
  lines.push('');
  lines.push('Итог:');
  lines.push(`  Скачано всего:   ${formatBytes(report.totalBytes)} (${formatInteger(report.totalBytes)} байт)`);
  lines.push(`  Общее время:     ${formatMs(report.totalTimeMs)}`);
  lines.push(`  Среднее время:   ${formatMs(report.avgRequestMs)}`);
  lines.push(`  Медиана:         ${formatMs(report.medianRequestMs)}`);
  lines.push(`  Мин / макс:      ${formatMs(report.minRequestMs)} / ${formatMs(report.maxRequestMs)}`);
  lines.push(
    `  Скорость:        ${report.throughput.mibPerSecond.toFixed(2)} МиБ/с (${report.throughput.mbitPerSecond.toFixed(2)} Мбит/с)`,
  );
  if (report.contentEncoding && report.contentEncoding !== 'identity') {
    lines.push(
      `  Примечание:      сервер вернул Content-Encoding: ${sanitizeForTerminal(report.contentEncoding, 50)}; считаны байты на проводе (сжатые).`,
    );
  }
  lines.push('');
  lines.push('Единицы: 1 МиБ = 1 048 576 байт; 1 Мбит = 1 000 000 бит. Среднее время — на один запрос целиком.');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const HELP_TEXT = `download-bench ${VERSION} — последовательный замер скорости скачивания URL.

Использование:
  node download-bench.mjs <URL> [опции]

Опции:
  -n, --requests <N>       число последовательных запросов (1..${MAX_REQUESTS}, по умолчанию ${DEFAULTS.requests})
  -t, --timeout <MS>       таймаут одного запроса целиком, мс (1..${MAX_TIMEOUT_MS}; по умолчанию ${DEFAULTS.timeoutMs})
      --max-bytes <N>      максимум байт на один ответ (по умолчанию ${DEFAULTS.maxBytes} = 512 МиБ)
      --max-redirects <N>  максимум редиректов (0..${MAX_REDIRECTS_LIMIT}, по умолчанию ${DEFAULTS.maxRedirects})
      --allow-private      разрешить loopback/частные адреса (НЕБЕЗОПАСНО; только для локальных тестов)
      --json               вывести отчёт в JSON
  -h, --help               показать эту справку

Примеры:
  node download-bench.mjs https://example.com/image.jpg
  node download-bench.mjs --requests 3 --timeout 120000 https://example.com/big.png
  node download-bench.mjs --json https://example.com/big.png

Единицы: объём — байты/МиБ (1 МиБ = 1 048 576 байт), скорость — МиБ/с и Мбит/с,
время — миллисекунды/секунды. Скорость = суммарный объём / общее время.
`;

/**
 * @param {string[]} argv
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream}} [io]
 * @returns {Promise<number>} код выхода
 */
export async function main(argv = process.argv.slice(2), io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;

  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    const message = error instanceof BenchError ? error.message : String(error);
    const jsonRequested = argv.some((arg) => arg === '--json' || arg.startsWith('--json='));
    if (jsonRequested) {
      stdout.write(
        `${JSON.stringify(
          { ok: false, error: { code: error instanceof BenchError ? error.code : 'USAGE', message: sanitizeForTerminal(message) } },
          null,
          2,
        )}\n`,
      );
    } else {
      stderr.write(`Ошибка аргументов: ${sanitizeForTerminal(message)}\n`);
      stderr.write('Справка: node download-bench.mjs --help\n');
    }
    return 2;
  }

  if (options.help) {
    stdout.write(HELP_TEXT);
    return 0;
  }

  const controller = new AbortController();
  const onSigint = () => controller.abort(new BenchError('ABORTED', 'Прервано пользователем (SIGINT)'));
  process.once('SIGINT', onSigint);

  try {
    const report = await runBenchmark({ ...options, signal: controller.signal });
    if (options.json) {
      stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } else {
      stdout.write(`${formatReport(report)}\n`);
    }
    return 0;
  } catch (error) {
    const benchError =
      error instanceof BenchError
        ? error
        : new BenchError('ERROR', error?.message ?? String(error), { cause: error });

    if (options.json) {
      stdout.write(
        `${JSON.stringify(
          { ok: false, error: { code: benchError.code, message: sanitizeForTerminal(benchError.message) } },
          null,
          2,
        )}\n`,
      );
    } else {
      stderr.write(`Ошибка [${benchError.code}]: ${sanitizeForTerminal(benchError.message)}\n`);
      if (benchError.code === 'BLOCKED_ADDRESS') {
        stderr.write('Подсказка: для локальных тестов есть флаг --allow-private (небезопасно).\n');
      }
    }
    return benchError.code === 'ABORTED' ? 130 : 1;
  } finally {
    process.removeListener('SIGINT', onSigint);
  }
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(`Непредвиденная ошибка: ${sanitizeForTerminal(error?.stack ?? String(error))}\n`);
    process.exitCode = 1;
  }
}
