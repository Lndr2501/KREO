const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ensureUserDataPath = () => {
  const custom = path.join(os.tmpdir(), 'kreo-gui');
  const cacheDir = path.join(custom, 'Cache');
  // Best effort cleanup to avoid stale/locked cache files.
  try { fs.rmSync(cacheDir, { recursive: true, force: true }); } catch (_) {}
  fs.mkdirSync(cacheDir, { recursive: true });
  app.setPath('userData', custom);
  app.setPath('cache', cacheDir);
  // Disable disk/gpu caches to avoid write/lock errors.
  app.commandLine.appendSwitch('disable-http-cache');
  app.commandLine.appendSwitch('disk-cache-size', '0');
  app.commandLine.appendSwitch('media-cache-size', '0');
  app.commandLine.appendSwitch('disable-gpu');
  app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
};

const createWindow = () => {
  const win = new BrowserWindow({
    width: 1000,
    height: 720,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    title: 'KREO Chat',
  });
  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
};

app.whenReady().then(() => {
  ensureUserDataPath();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
