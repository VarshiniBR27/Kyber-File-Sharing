import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const storageDir = path.join(rootDir, 'storage');
const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_FILE_BYTES = 25 * 1024 * 1024;

await mkdir(storageDir, { recursive: true });

app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '20kb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1 }
});

const validId = (id) => /^[0-9a-f-]{36}$/i.test(id);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'KyberShare API', maxFileBytes: MAX_FILE_BYTES });
});

app.post('/api/files', upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Encrypted file is required.' });

    let metadata;
    try {
      metadata = JSON.parse(req.body.metadata || '{}');
    } catch {
      return res.status(400).json({ error: 'Metadata must be valid JSON.' });
    }

    const required = ['kemCiphertext', 'iv', 'salt', 'originalName', 'contentType'];
    if (!required.every((key) => typeof metadata[key] === 'string' && metadata[key].length > 0)) {
      return res.status(400).json({ error: 'Required encryption metadata is missing.' });
    }
    if (metadata.kemCiphertext.length > 5000 || metadata.iv.length > 100 || metadata.salt.length > 100 ||
        metadata.originalName.length > 255 || metadata.contentType.length > 150) {
      return res.status(400).json({ error: 'Metadata exceeds allowed limits.' });
    }

    const id = randomUUID();
    const safeMetadata = {
      id,
      kemCiphertext: metadata.kemCiphertext,
      iv: metadata.iv,
      salt: metadata.salt,
      originalName: path.basename(metadata.originalName).replace(/[\r\n]/g, '_'),
      contentType: metadata.contentType,
      encryptedBytes: req.file.size,
      createdAt: new Date().toISOString()
    };

    await writeFile(path.join(storageDir, id + '.bin'), req.file.buffer, { flag: 'wx' });
    await writeFile(path.join(storageDir, id + '.json'), JSON.stringify(safeMetadata, null, 2), { flag: 'wx' });

    res.status(201).json({ id, encryptedBytes: req.file.size, createdAt: safeMetadata.createdAt });
  } catch (error) {
    next(error);
  }
});

app.get('/api/files/:id', async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid share ID.' });
    const metadata = await readFile(path.join(storageDir, req.params.id + '.json'), 'utf8')
      .then(JSON.parse)
      .catch((error) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
    if (!metadata) return res.status(404).json({ error: 'Share not found.' });
    res.json(metadata);
  } catch (error) {
    next(error);
  }
});

app.get('/api/files/:id/blob', async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid share ID.' });
    const filePath = path.join(storageDir, req.params.id + '.bin');
    const data = await readFile(filePath).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (!data) return res.status(404).json({ error: 'Encrypted file not found.' });
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store');
    res.send(data);
  } catch (error) {
    next(error);
  }
});

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(rootDir, 'dist')));
  app.get('*path', (_req, res) => res.sendFile(path.join(rootDir, 'dist', 'index.html')));
}

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File is too large. Maximum size is 25 MB.' });
  }
  console.error(error);
  res.status(500).json({ error: 'Server error. Check the server terminal.' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`KyberShare API listening at http://127.0.0.1:${PORT}`);
});
