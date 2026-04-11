/**
 * Electron main process — loads the Vite app (dev server or built dist/).
 */
const { app, BrowserWindow, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const { pathToFileURL } = require("url");

const DEV_URL = process.env.VITE_DEV_SERVER_URL || "http://127.0.0.1:8080";

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 960,
    minHeight: 640,
    show: false,
    title: "QuantumShield",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.once("ready-to-show", () => win.show());

  const useDevServer = process.env.ELECTRON_DEV === "1";
  const distHtml = path.join(__dirname, "..", "dist", "index.html");

  if (useDevServer) {
    win.loadURL(DEV_URL).catch((err) => {
      console.error("Failed to load dev server. Is Vite running on port 8080?", err);
    });
    win.webContents.openDevTools({ mode: "detach" });
  } else if (fs.existsSync(distHtml)) {
    win.loadURL(pathToFileURL(distHtml).href);
  } else {
    win.loadURL(DEV_URL).catch(() => {
      /* last resort */
    });
  }

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
