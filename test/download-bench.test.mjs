import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import zlib from 'node:zlib';

import {
  BenchError,
  blockedAddressReason,
  formatReport,
  isPublicAddress,
  main,
  parseArgs,
  runBenchmark,
  sanitizeForTerminal,
} from '../download-bench.mjs';

const MIB = 1024 * 1024;

async function startServer(handler) {
  const server = http.createServer(handler);
  server.on('clientError', (error, socket) => {
    socket.destroy();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  return {
    server,
    url: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function makeOptions(url, overrides = {}) {
  return {
    target: new URL(url),
    requests: 2,
    timeoutMs: 3000,
    maxBytes: 32 * MIB,
    maxRedirects: 5,
    allowPrivate: true,
    ...overrides,
  };
}

async function expectFailure(options, codes) {
  const report = await runBenchmark(options);
  assert.equal(report.ok, false, 'ожидался частичный отчёт с ok:false');
  const expected = Array.isArray(codes) ? codes : [codes];
  assert.ok(
    expected.includes(report.error?.code),
    `ожидался код ${expected.join('|')}, получен ${report.error?.code}: ${report.error?.message}`,
  );
  assert.equal(report.completedRequests, report.perRequest.length);
  return report;
}

function writeTo(chunks) {
  return {
    write(value) {
      chunks.push(String(value));
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// Аргументы и URL
// ---------------------------------------------------------------------------

test('parseArgs: значения по умолчанию', () => {
  const options = parseArgs(['https://example.com/image.png']);
  assert.equal(options.requests, 10);
  assert.equal(options.timeoutMs, 60_000);
  assert.equal(options.maxBytes, 512 * MIB);
  assert.equal(options.maxRedirects, 5);
  assert.equal(options.allowPrivate, false);
  assert.equal(options.json, false);
  assert.equal(options.help, false);
  assert.equal(options.version, false);
  assert.equal(options.target.href, 'https://example.com/image.png');
});

test('parseArgs: флаги, = и значения', () => {
  const options = parseArgs([
    '--requests=2',
    '-t',
    '500',
    '--max-bytes',
    '1024',
    '--max-redirects',
    '0',
    '--json',
    '--allow-private',
    'http://example.com/a.png',
  ]);
  assert.equal(options.requests, 2);
  assert.equal(options.timeoutMs, 500);
  assert.equal(options.maxBytes, 1024);
  assert.equal(options.maxRedirects, 0);
  assert.equal(options.json, true);
  assert.equal(options.allowPrivate, true);
});

test('parseArgs: фрагмент URL отбрасывается, query сохраняется', () => {
  const options = parseArgs(['https://example.com/a.png?x=1#section']);
  assert.equal(options.target.hash, '');
  assert.equal(options.target.search, '?x=1');
});

test('parseArgs: --help работает без URL', () => {
  const options = parseArgs(['--help']);
  assert.equal(options.help, true);
  assert.equal(options.target, null);
});

test('parseArgs: -h приоритетнее ошибок разбора', () => {
  const options = parseArgs(['-h', '--bad-flag']);
  assert.equal(options.help, true);
  assert.equal(options.target, null);
});

test('parseArgs: --help приоритетнее ошибок, идущих до него', () => {
  const options = parseArgs(['--bad-flag', '--timeout', 'abc', '--help']);
  assert.equal(options.help, true);
  assert.equal(options.target, null);
});

test('parseArgs: --help после -- уже не флаг', () => {
  assert.throws(
    () => parseArgs(['--', '--help']),
    (error) => error instanceof BenchError && error.code === 'USAGE',
  );
});

test('parseArgs: --version работает без URL', () => {
  const options = parseArgs(['--version']);
  assert.equal(options.version, true);
  assert.equal(options.target, null);
});

test('parseArgs: некорректные аргументы', () => {
  const cases = [
    [],
    ['ftp://example.com/file'],
    ['file:///etc/passwd'],
    ['javascript:alert(1)'],
    ['http://user:pass@example.com/'],
    ['http://example.com:0/'],
    ['http://example.com/a', 'http://example.com/b'],
    ['--requests', '0', 'http://example.com/'],
    ['--requests', '1.5', 'http://example.com/'],
    ['--requests', 'abc', 'http://example.com/'],
    ['--timeout', '0', 'http://example.com/'],
    ['--max-bytes', '-1', 'http://example.com/'],
    ['--max-redirects', '999', 'http://example.com/'],
    ['--bogus', 'http://example.com/'],
    ['http://example.com/\n'],
  ];
  for (const argv of cases) {
    assert.throws(() => parseArgs(argv), (error) => error instanceof BenchError && error.code === 'USAGE', argv.join(' '));
  }
});

// ---------------------------------------------------------------------------
// Классификация адресов
// ---------------------------------------------------------------------------

test('блокируются приватные, loopback и служебные адреса', () => {
  const blocked = [
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '127.1.2.3',
    '169.254.169.254',
    '172.16.0.1',
    '172.31.255.255',
    '192.0.0.1',
    '192.0.2.5',
    '192.88.99.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.51.100.7',
    '203.0.113.9',
    '224.0.0.1',
    '240.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:10.0.0.1',
    '::ffff:192.168.0.1',
    '::7f00:1',
    '64:ff9b::a00:1',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    'ff02::1',
    '2001:db8::1',
    '2001:0::1',
    '2001:2::1',
    '2001:10::1',
    '2001:20::1',
    '2001:4:112::1',
    '3fff::1',
    '2002:7f00:1::',
    '2002:c0a8:101::',
  ];
  for (const address of blocked) {
    assert.equal(isPublicAddress(address), false, `${address} должен быть заблокирован`);
    assert.ok(blockedAddressReason(address), `${address} должен иметь причину блокировки`);
  }
});

test('публичные адреса не блокируются', () => {
  const allowed = [
    '1.1.1.1',
    '8.8.8.8',
    '8.8.4.4',
    '93.184.216.34',
    '185.199.108.153',
    '208.67.222.222',
    '2001:4860:4860::8888',
    '2606:4700:4700::1111',
    '2a03:2880:f10c:83:face:b00c:0:25de',
    '::ffff:8.8.8.8',
  ];
  for (const address of allowed) {
    assert.equal(isPublicAddress(address), true, `${address} должен быть разрешён`);
    assert.equal(blockedAddressReason(address), null);
  }
  assert.equal(isPublicAddress('not-an-ip'), false);
});

// ---------------------------------------------------------------------------
// Защита вывода
// ---------------------------------------------------------------------------

test('sanitizeForTerminal: C0/C1, ESC и bidi-контролы', () => {
  const input = [
    '\u001b[31mred',
    '\u009b',
    '\u061c',
    '\u200e',
    '\u200f',
    '\u202a',
    '\u202b',
    '\u202c',
    '\u202d',
    '\u202e',
    '\u2066',
    '\u2067',
    '\u2068',
    '\u2069',
    '\u2028',
    '\u2029',
    'done',
  ].join('');

  const output = sanitizeForTerminal(input);
  assert.doesNotMatch(
    output,
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069]/,
  );
  assert.match(output, /\\x1b\[31mred/);
  assert.match(output, /\\x9b/);
  assert.match(output, /\\u061c/);
  assert.match(output, /\\u202e/);
  assert.match(output, /\\u2066/);
  assert.match(output, /\\u2028/);
});

test('runBenchmark: requests = 0 отклоняется, а не падает с TypeError', async () => {
  await assert.rejects(
    runBenchmark({
      target: new URL('http://127.0.0.1:1/'),
      requests: 0,
      timeoutMs: 1000,
      maxBytes: 1024,
      maxRedirects: 0,
      allowPrivate: true,
    }),
    (error) => error instanceof RangeError && /options\.requests/.test(error.message),
  );
});

// ---------------------------------------------------------------------------
// Скачивание
// ---------------------------------------------------------------------------

test('скачивает N раз последовательно, считает байты и время', async () => {
  let active = 0;
  let maxActive = 0;
  let served = 0;
  const body = Buffer.alloc(1024, 0x61);

  const server = await startServer((request, response) => {
    active += 1;
    maxActive = Math.max(maxActive, active);
    served += 1;
    assert.equal(request.headers['accept-encoding'], 'identity');
    assert.match(String(request.headers['user-agent']), /^download-bench\//);
    response.writeHead(200, {
      'content-type': 'image/png',
      'content-length': body.length,
    });
    response.end(body);
    response.on('finish', () => {
      active -= 1;
    });
  });

  try {
    const report = await runBenchmark(
      makeOptions(`${server.url}/image.png#frag`, { requests: 3 }),
    );

    assert.equal(report.ok, true);
    assert.equal(report.requests, 3);
    assert.equal(report.status, 200);
    assert.equal(report.contentType, 'image/png');
    assert.equal(report.compressed, false);
    assert.equal(report.allowPrivate, true);
    assert.match(formatReport(report), /--allow-private/);
    assert.equal(report.totalBytes, body.length * 3);
    assert.equal(report.perRequest.length, 3);
    assert.deepEqual(
      report.perRequest.map((item) => item.bytes),
      [body.length, body.length, body.length],
    );
    assert.equal(served, 3);
    assert.equal(maxActive, 1, 'запросы должны идти строго последовательно');
    assert.ok(report.avgRequestMs >= 0);
    assert.ok(report.medianRequestMs >= 0);
    assert.ok(report.minRequestMs <= report.maxRequestMs);
    assert.ok(report.throughput.mibPerSecond > 0);
    assert.ok(Number.isFinite(report.throughput.mbitPerSecond));
    assert.equal(JSON.parse(JSON.stringify(report)).ok, true);
  } finally {
    await server.close();
  }
});

test('пустой ответ 204 — это успех с нулевым объёмом', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(204);
    response.end();
  });

  try {
    const report = await runBenchmark(makeOptions(server.url, { requests: 1 }));
    assert.equal(report.status, 204);
    assert.equal(report.totalBytes, 0);
    assert.equal(report.throughput.mibPerSecond, 0);
    assert.ok(Number.isFinite(report.throughput.mibPerSecond));
  } finally {
    await server.close();
  }
});

test('сжатый ответ помечается compressed, объём считается по байтам на проводе', async () => {
  const payload = Buffer.from('a'.repeat(10_000));
  const gzipped = zlib.gzipSync(payload);
  const server = await startServer((request, response) => {
    response.writeHead(200, {
      'content-encoding': 'gzip',
      'content-length': gzipped.length,
    });
    response.end(gzipped);
  });

  try {
    const report = await runBenchmark(makeOptions(server.url, { requests: 1 }));
    assert.equal(report.ok, true);
    assert.equal(report.compressed, true);
    assert.equal(report.contentEncoding, 'gzip');
    assert.equal(report.totalBytes, gzipped.length);
    assert.equal(report.perRequest[0].contentEncoding, 'gzip');
    assert.match(formatReport(report), /сжаты/);
  } finally {
    await server.close();
  }
});

test('HTTP 4xx/5xx — ошибка HTTP_STATUS', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('nope');
  });

  try {
    const report = await expectFailure(
      makeOptions(server.url, { requests: 1 }),
      'HTTP_STATUS',
    );
    assert.equal(report.completedRequests, 0);
    assert.deepEqual(report.perRequest, []);
    assert.equal(report.failedAt, 1);
    assert.equal(report.totalBytes, 0);
  } finally {
    await server.close();
  }
});

test('ошибка на середине сохраняет замеры завершённых запросов', async () => {
  const body = Buffer.alloc(512, 0x65);
  let served = 0;
  const server = await startServer((request, response) => {
    served += 1;
    if (served === 3) {
      response.writeHead(503);
      response.end('temporary');
      return;
    }
    response.writeHead(200, { 'content-length': body.length });
    response.end(body);
  });

  try {
    const report = await runBenchmark(makeOptions(server.url, { requests: 5 }));

    assert.equal(report.ok, false);
    assert.equal(report.error.code, 'HTTP_STATUS');
    assert.equal(report.failedAt, 3);
    assert.equal(report.completedRequests, 2);
    assert.equal(report.perRequest.length, 2);
    assert.deepEqual(
      report.perRequest.map((item) => item.index),
      [1, 2],
    );
    assert.equal(report.totalBytes, body.length * 2);
    assert.equal(report.status, 200);
    assert.ok(Number.isFinite(report.avgRequestMs));
    assert.ok(Number.isFinite(report.throughput.mibPerSecond));

    const text = formatReport(report);
    assert.match(text, /Частичный итог \(2 из 5\)/);
    assert.match(text, /Ошибка \[HTTP_STATUS\] на запросе 3/);
    assert.match(text, /В отчёт включены только успешно завершённые запросы/);
  } finally {
    await server.close();
  }
});

test('таймаут на запрос целиком', async () => {
  const server = await startServer(() => {
    // Намеренно не отвечаем.
  });

  try {
    const started = performance.now();
    await expectFailure(
      makeOptions(server.url, { requests: 1, timeoutMs: 150 }),
      'TIMEOUT',
    );
    assert.ok(performance.now() - started < 3000);
  } finally {
    await server.close();
  }
});

test('Content-Length больше лимита — ошибка TOO_LARGE до чтения тела', async () => {
  const server = await startServer((request, response) => {
    response.on('error', () => {});
    response.writeHead(200, { 'content-length': 4096 });
    response.end(Buffer.alloc(4096));
  });

  try {
    await expectFailure(
      makeOptions(server.url, { requests: 1, maxBytes: 1024 }),
      'TOO_LARGE',
    );
  } finally {
    await server.close();
  }
});

test('chunked-ответ больше лимита — ошибка TOO_LARGE', async () => {
  const server = await startServer((request, response) => {
    response.on('error', () => {});
    response.writeHead(200);
    response.write(Buffer.alloc(2048));
    response.end();
  });

  try {
    await expectFailure(
      makeOptions(server.url, { requests: 1, maxBytes: 1024 }),
      'TOO_LARGE',
    );
  } finally {
    await server.close();
  }
});

test('оборванный ответ — ошибка', async () => {
  const server = await startServer((request, response) => {
    response.on('error', () => {});
    response.writeHead(200, { 'content-length': 1000 });
    response.write(Buffer.alloc(100));
    setTimeout(() => response.destroy(), 20);
  });

  try {
    await expectFailure(makeOptions(server.url, { requests: 1 }), ['TRUNCATED', 'NETWORK']);
  } finally {
    await server.close();
  }
});

test('редиректы поддерживаются, время и байты считаются по финальному ответу', async () => {
  const body = Buffer.alloc(512, 0x62);
  const server = await startServer((request, response) => {
    if (request.url === '/start') {
      response.writeHead(302, { location: '/middle' });
      response.end();
      return;
    }
    if (request.url === '/middle') {
      response.writeHead(301, { location: '/final' });
      response.end();
      return;
    }
    response.writeHead(200, {
      'content-type': 'image/jpeg',
      'content-length': body.length,
    });
    response.end(body);
  });

  try {
    const report = await runBenchmark(
      makeOptions(`${server.url}/start`, { requests: 2 }),
    );
    assert.equal(report.finalUrl, `${server.url}/final`);
    assert.equal(report.totalBytes, body.length * 2);
    assert.equal(report.status, 200);
  } finally {
    await server.close();
  }
});

test('лимит редиректов', async () => {
  const server = await startServer((request, response) => {
    const url = new URL(request.url, 'http://placeholder');
    const step = Number(url.searchParams.get('step') ?? '0');
    response.writeHead(302, { location: `/r?step=${step + 1}` });
    response.end();
  });

  try {
    await expectFailure(
      makeOptions(`${server.url}/r`, { requests: 1, maxRedirects: 2 }),
      'REDIRECT_LIMIT',
    );
  } finally {
    await server.close();
  }
});

test('цикл редиректов обнаруживается', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(302, { location: request.url === '/a' ? '/b' : '/a' });
    response.end();
  });

  try {
    await expectFailure(makeOptions(`${server.url}/a`, { requests: 1 }), 'REDIRECT_LOOP');
  } finally {
    await server.close();
  }
});

test('редирект без Location — ошибка', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(302);
    response.end();
  });

  try {
    await expectFailure(
      makeOptions(server.url, { requests: 1 }),
      'REDIRECT_NO_LOCATION',
    );
  } finally {
    await server.close();
  }
});

test('редирект на file:// запрещён', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(302, { location: 'file:///etc/passwd' });
    response.end();
  });

  try {
    await expectFailure(
      makeOptions(server.url, { requests: 1 }),
      'REDIRECT_PROTOCOL',
    );
  } finally {
    await server.close();
  }
});

test('--max-redirects 0 запрещает даже один редирект', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(302, { location: '/target' });
    response.end();
  });

  try {
    await expectFailure(
      makeOptions(server.url, { requests: 1, maxRedirects: 0 }),
      'REDIRECT_LIMIT',
    );
  } finally {
    await server.close();
  }
});

test('учётные данные из Location не пересылаются', async () => {
  let authorization = 'unset';
  const server = await startServer((request, response) => {
    if (request.url === '/start') {
      response.writeHead(302, {
        location: `http://user:pass@${request.headers.host}/final`,
      });
      response.end();
      return;
    }
    authorization = request.headers.authorization ?? null;
    response.writeHead(200, { 'content-length': 2 });
    response.end('ok');
  });

  try {
    const report = await runBenchmark(makeOptions(`${server.url}/start`, { requests: 1 }));
    assert.equal(report.finalUrl, `${server.url}/final`);
    assert.equal(authorization, null);
  } finally {
    await server.close();
  }
});

test('таймаут срабатывает и при медленном теле ответа', async () => {
  let timer;
  const server = await startServer((request, response) => {
    response.on('error', () => {});
    response.writeHead(200, { 'content-length': 100_000 });
    timer = setInterval(() => {
      response.write(Buffer.alloc(10));
    }, 30);
    response.on('close', () => clearInterval(timer));
  });

  try {
    const started = performance.now();
    await expectFailure(
      makeOptions(server.url, { requests: 1, timeoutMs: 150 }),
      'TIMEOUT',
    );
    assert.ok(performance.now() - started < 3000);
  } finally {
    if (timer) clearInterval(timer);
    await server.close();
  }
});

test('внешний AbortSignal прерывает прогон с частичным отчётом', async () => {
  const server = await startServer(() => {
    // Намеренно не отвечаем.
  });
  const controller = new AbortController();
  let abortTimer;

  try {
    const promise = runBenchmark(
      makeOptions(server.url, {
        requests: 5,
        timeoutMs: 5000,
        signal: controller.signal,
      }),
    );
    abortTimer = setTimeout(() => controller.abort(new BenchError('ABORTED', 'остановлено тестом')), 50);
    const report = await promise;
    assert.equal(report.ok, false);
    assert.equal(report.error.code, 'ABORTED');
    assert.equal(report.completedRequests, 0);
    assert.equal(report.failedAt, 1);
  } finally {
    clearTimeout(abortTimer);
    await server.close();
  }
});

test('без --allow-private локальный адрес блокируется до запроса', async () => {
  let served = 0;
  const server = await startServer((request, response) => {
    served += 1;
    response.end('nope');
  });

  try {
    const report = await expectFailure(
      makeOptions(server.url, { requests: 1, allowPrivate: false }),
      'BLOCKED_ADDRESS',
    );
    assert.equal(served, 0);
    assert.equal(report.completedRequests, 0);
  } finally {
    await server.close();
  }
});

test('--allow-private: false блокирует localhost по результату DNS', async () => {
  const server = await startServer((request, response) => response.end('ok'));
  const { port } = server.server.address();
  const target = new URL(`http://localhost:${port}/`);

  try {
    await expectFailure(
      makeOptions(target.href, { requests: 1, allowPrivate: false }),
      'BLOCKED_ADDRESS',
    );
  } finally {
    await server.close();
  }
});

// ---------------------------------------------------------------------------
// CLI (main)
// ---------------------------------------------------------------------------

test('main: --json печатает машинно-читаемый отчёт', async () => {
  const body = Buffer.alloc(256, 0x63);
  const server = await startServer((request, response) => {
    response.writeHead(200, { 'content-length': body.length });
    response.end(body);
  });

  try {
    const stdout = [];
    const stderr = [];
    const code = await main(
      ['--json', '--allow-private', '--requests', '1', server.url],
      { stdout: writeTo(stdout), stderr: writeTo(stderr) },
    );

    assert.equal(code, 0);
    assert.equal(stderr.join(''), '');
    const report = JSON.parse(stdout.join(''));
    assert.equal(report.ok, true);
    assert.equal(report.requests, 1);
    assert.equal(report.totalBytes, body.length);
    assert.equal(report.allowPrivate, true);
    assert.equal(report.compressed, false);
    assert.match(report.units.throughput, /МиБ\/с/);
  } finally {
    await server.close();
  }
});

test('main: --version', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main(['--version'], {
    stdout: writeTo(stdout),
    stderr: writeTo(stderr),
  });
  assert.equal(code, 0);
  assert.match(stdout.join(''), /^download-bench \d+\.\d+\.\d+\n$/);
  assert.equal(stderr.join(''), '');
});

test('main: --help приоритетнее ошибки до него', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main(['--bad-flag', '--help'], {
    stdout: writeTo(stdout),
    stderr: writeTo(stderr),
  });
  assert.equal(code, 0);
  assert.match(stdout.join(''), /Использование:/);
  assert.equal(stderr.join(''), '');
});

test('main: ошибка HTTP в --json режиме', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(500);
    response.end();
  });

  try {
    const stdout = [];
    const stderr = [];
    const code = await main(
      ['--json', '--allow-private', '--requests', '1', server.url],
      { stdout: writeTo(stdout), stderr: writeTo(stderr) },
    );

    assert.equal(code, 1);
    assert.equal(stderr.join(''), '');
    const payload = JSON.parse(stdout.join(''));
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, 'HTTP_STATUS');
    assert.equal(payload.completedRequests, 0);
    assert.equal(payload.failedAt, 1);
    assert.deepEqual(payload.perRequest, []);
    assert.equal(payload.totalBytes, 0);
  } finally {
    await server.close();
  }
});

test('main: текстовый частичный отчёт при ошибке', async () => {
  const server = await startServer((request, response) => {
    response.writeHead(500);
    response.end();
  });

  try {
    const stdout = [];
    const stderr = [];
    const code = await main(
      ['--allow-private', '--requests', '2', server.url],
      { stdout: writeTo(stdout), stderr: writeTo(stderr) },
    );

    assert.equal(code, 1);
    const text = stdout.join('');
    assert.match(text, /Частичный итог \(0 из 2\)/);
    assert.match(text, /Ошибка \[HTTP_STATUS\] на запросе 1/);
    assert.match(text, /В отчёт включены только успешно завершённые запросы/);
  } finally {
    await server.close();
  }
});

test('main: внешний signal даёт частичный отчёт и код 130', async () => {
  const server = await startServer(() => {
    // Намеренно не отвечаем.
  });
  const controller = new AbortController();
  const stdout = [];
  const stderr = [];
  let timer;

  try {
    timer = setTimeout(() => controller.abort(new BenchError('ABORTED', 'остановлено тестом')), 50);
    const code = await main(
      ['--json', '--allow-private', '--requests', '2', server.url],
      {
        stdout: writeTo(stdout),
        stderr: writeTo(stderr),
        signal: controller.signal,
      },
    );

    assert.equal(code, 130);
    const payload = JSON.parse(stdout.join(''));
    assert.equal(payload.ok, false);
    assert.equal(payload.error.code, 'ABORTED');
    assert.equal(payload.completedRequests, 0);
  } finally {
    clearTimeout(timer);
    await server.close();
  }
});

test('main: ошибка аргументов даёт код 2', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main([], { stdout: writeTo(stdout), stderr: writeTo(stderr) });
  assert.equal(code, 2);
  assert.match(stderr.join(''), /URL/);
});

test('main: ошибка аргументов в --json режиме тоже JSON', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main(['--json', 'ftp://example.com/file'], {
    stdout: writeTo(stdout),
    stderr: writeTo(stderr),
  });
  assert.equal(code, 2);
  assert.equal(stderr.join(''), '');
  const payload = JSON.parse(stdout.join(''));
  assert.equal(payload.ok, false);
  assert.equal(payload.error.code, 'USAGE');
});

test('main: --json=foo — ошибка, а не JSON-режим', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main(['--json=foo', 'http://example.com/file'], {
    stdout: writeTo(stdout),
    stderr: writeTo(stderr),
  });
  assert.equal(code, 2);
  assert.equal(stdout.join(''), '');
  assert.match(stderr.join(''), /не принимает значение/);
});

test('main: --json в позиции значения не включает JSON', async () => {
  const stdout = [];
  const stderr = [];
  const code = await main(['--requests', '--json', 'http://example.com/file'], {
    stdout: writeTo(stdout),
    stderr: writeTo(stderr),
  });
  assert.equal(code, 2);
  assert.equal(stdout.join(''), '');
  assert.match(stderr.join(''), /ожидается целое число/);
});

test('formatReport: содержит единицы и итоговую скорость', () => {
  const report = {
    target: 'https://example.com/a.png',
    finalUrl: 'https://example.com/a.png',
    requests: 2,
    totalBytes: 2 * MIB,
    totalTimeMs: 1000,
    avgRequestMs: 500,
    medianRequestMs: 500,
    minRequestMs: 400,
    maxRequestMs: 600,
    throughput: { mibPerSecond: 2, mbitPerSecond: 16.777216 },
    contentEncoding: null,
    perRequest: [
      { index: 1, bytes: MIB, durationMs: 400 },
      { index: 2, bytes: MIB, durationMs: 600 },
    ],
  };
  const text = formatReport(report);
  assert.match(text, /МиБ\/с/);
  assert.match(text, /Мбит\/с/);
  assert.match(text, /Скачано всего/);
  assert.match(text, /Среднее время/);
});
