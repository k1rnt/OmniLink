import { useState, useCallback } from 'react';
import { check, Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

export interface UpdateInfo {
  available: boolean;
  currentVersion: string;
  newVersion: string | null;
  releaseNotes: string | null;
}

export interface UpdateProgress {
  status: 'idle' | 'checking' | 'downloading' | 'ready' | 'error';
  downloadedBytes: number;
  totalBytes: number;
}

export function useUpdater() {
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo>({
    available: false,
    currentVersion: '0.1.0',
    newVersion: null,
    releaseNotes: null,
  });
  const [progress, setProgress] = useState<UpdateProgress>({
    status: 'idle',
    downloadedBytes: 0,
    totalBytes: 0,
  });
  const [error, setError] = useState<string | null>(null);
  const [pendingUpdate, setPendingUpdate] = useState<Update | null>(null);

  const checkForUpdates = useCallback(async () => {
    setProgress({ status: 'checking', downloadedBytes: 0, totalBytes: 0 });
    setError(null);

    try {
      const update = await check();

      if (update) {
        setUpdateInfo({
          available: true,
          currentVersion: update.currentVersion,
          newVersion: update.version,
          releaseNotes: update.body ?? null,
        });
        setPendingUpdate(update);
      } else {
        setUpdateInfo((prev) => ({ ...prev, available: false }));
        setPendingUpdate(null);
      }

      setProgress({ status: 'idle', downloadedBytes: 0, totalBytes: 0 });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.warn("Update check failed:", msg);
      setError(msg);
      setProgress({ status: 'error', downloadedBytes: 0, totalBytes: 0 });
    }
  }, []);

  const downloadAndInstall = useCallback(async () => {
    if (!pendingUpdate) return;

    setProgress({ status: 'downloading', downloadedBytes: 0, totalBytes: 0 });
    setError(null);

    try {
      let downloadedBytes = 0;
      let totalBytes = 0;

      await pendingUpdate.downloadAndInstall((event) => {
        switch (event.event) {
          case 'Started':
            totalBytes = event.data.contentLength ?? 0;
            setProgress({ status: 'downloading', downloadedBytes: 0, totalBytes });
            break;
          case 'Progress':
            downloadedBytes += event.data.chunkLength;
            setProgress({ status: 'downloading', downloadedBytes, totalBytes });
            break;
          case 'Finished':
            setProgress({ status: 'ready', downloadedBytes: totalBytes, totalBytes });
            break;
        }
      });

      setProgress({ status: 'ready', downloadedBytes: totalBytes, totalBytes });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setProgress({ status: 'error', downloadedBytes: 0, totalBytes: 0 });
    }
  }, [pendingUpdate]);

  const restartApp = useCallback(async () => {
    await relaunch();
  }, []);

  return {
    updateInfo,
    progress,
    error,
    checkForUpdates,
    downloadAndInstall,
    restartApp,
  };
}
