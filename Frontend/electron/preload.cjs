/**
 * Preload — keep minimal; renderer stays a normal web app (no Node in UI).
 */
const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  platform: process.platform,
});
