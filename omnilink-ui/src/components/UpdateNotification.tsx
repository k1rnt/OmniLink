import { useState } from 'react';
import { useUpdater } from '../hooks/useUpdater';

export default function UpdateNotification() {
  const { updateInfo, progress, error, downloadAndInstall, restartApp, checkForUpdates } = useUpdater();
  const [dismissed, setDismissed] = useState(false);

  // Don't show if dismissed, no update, or still checking
  if (dismissed || (!updateInfo.available && progress.status !== 'checking' && progress.status !== 'error')) {
    return null;
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const getProgressPercent = () => {
    if (progress.totalBytes === 0) return 0;
    return Math.round((progress.downloadedBytes / progress.totalBytes) * 100);
  };

  return (
    <div className="update-notification">
      {progress.status === 'checking' && (
        <div className="update-content">
          <span className="update-icon">&#8635;</span>
          <span>Checking for updates...</span>
        </div>
      )}

      {progress.status === 'idle' && updateInfo.available && (
        <div className="update-content">
          <span className="update-icon">&#8593;</span>
          <div className="update-info">
            <span className="update-title">Update available: v{updateInfo.newVersion}</span>
          </div>
          <button className="btn btn-primary" onClick={downloadAndInstall}>
            Download
          </button>
          <button className="btn update-dismiss" onClick={() => setDismissed(true)}>
            Later
          </button>
        </div>
      )}

      {progress.status === 'downloading' && (
        <div className="update-content">
          <span className="update-icon">&#8595;</span>
          <div className="update-progress">
            <span>Downloading... {getProgressPercent()}%</span>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${getProgressPercent()}%` }} />
            </div>
            <span className="progress-bytes">
              {formatBytes(progress.downloadedBytes)} / {formatBytes(progress.totalBytes)}
            </span>
          </div>
        </div>
      )}

      {progress.status === 'ready' && (
        <div className="update-content">
          <span className="update-icon update-success">&#10003;</span>
          <span>Update ready! Restart to apply.</span>
          <button className="btn btn-primary" onClick={restartApp}>
            Restart Now
          </button>
        </div>
      )}

      {progress.status === 'error' && error && (
        <div className="update-content update-error">
          <span className="update-icon">&#9888;</span>
          <span>Update check failed</span>
          <button className="btn" onClick={checkForUpdates}>
            Retry
          </button>
          <button className="btn update-dismiss" onClick={() => setDismissed(true)}>
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}
