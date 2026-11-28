<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  interface AppInfo {
    identity: {
      name: string;
      version: string;
      identifier: string;
      description: string;
    };
    platform: {
      os: string;
      arch: string;
      available_parallelism: number;
      default_rayon_threads: number;
    };
    capabilities: {
      file_extension: string;
      current_version: number;
      min_supported_version: number;
      supports_encryption: boolean;
      default_algorithm: string;
      supported_algorithms: Array<{
        id: string;
        name: string;
        cryptographic: boolean;
        is_default: boolean;
      }>;
    };
    initialized: boolean;
  }

  interface AppStatus {
    initialized: boolean;
    shutting_down: boolean;
    uptime_ms: number;
    active_scan_count: number;
    loaded_snapshot_count: number;
  }

  let appInfo = $state<AppInfo | null>(null);
  let appStatus = $state<AppStatus | null>(null);
  let pingResult = $state<string | null>(null);
  let errorMsg = $state<string | null>(null);

  async function refreshBackendState() {
    errorMsg = null;
    try {
      const [pong, info, status] = await Promise.all([
        invoke<string>("ping"),
        invoke<AppInfo>("get_app_info"),
        invoke<AppStatus>("get_app_status"),
      ]);
      pingResult = pong;
      appInfo = info;
      appStatus = status;
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    }
  }

  onMount(() => {
    void refreshBackendState();
  });
</script>

<main class="shell">
  <header class="header">
    <h1>{appInfo?.identity.name ?? "BulkHash"}</h1>
    <p class="subtitle">
      {#if appInfo}
        v{appInfo.identity.version} · {appInfo.platform.os} ({appInfo.platform.arch})
      {:else}
        Desktop Runtime
      {/if}
    </p>
  </header>

  {#if errorMsg}
    <section class="card error">
      <h2>IPC Verbindung fehlgeschlagen</h2>
      <p>{errorMsg}</p>
      <button type="button" onclick={refreshBackendState}>Erneut prüfen</button>
    </section>
  {:else if appInfo && appStatus}
    <section class="card">
      <div class="row">
        <span>Backend-Status</span>
        <strong>{appStatus.initialized && pingResult === "pong" ? "Bereit" : "Initialisiert..."}</strong>
      </div>
      <div class="row">
        <span>Format</span>
        <strong>
          .{appInfo.capabilities.file_extension} v{appInfo.capabilities.current_version}
          (ab v{appInfo.capabilities.min_supported_version})
        </strong>
      </div>
      <div class="row">
        <span>Threads</span>
        <strong>{appInfo.platform.default_rayon_threads} / {appInfo.platform.available_parallelism}</strong>
      </div>
      <div class="row">
        <span>Algorithmen</span>
        <strong>{appInfo.capabilities.supported_algorithms.map((a) => a.name).join(", ")}</strong>
      </div>
      <div class="row">
        <span>Aktive Scans / Geladene Snapshots</span>
        <strong>{appStatus.active_scan_count} / {appStatus.loaded_snapshot_count}</strong>
      </div>
    </section>
  {:else}
    <section class="card">
      <p>Verbinde mit Tauri-Backend…</p>
    </section>
  {/if}
</main>

<style>
  :root {
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #0f172a;
    background-color: #f8fafc;
  }

  .shell {
    max-width: 720px;
    margin: 0 auto;
    padding: 3rem 1.5rem;
  }

  .header {
    margin-bottom: 1.5rem;
  }

  h1 {
    margin: 0;
    font-size: 2rem;
  }

  .subtitle {
    margin: 0.25rem 0 0;
    color: #475569;
  }

  .card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .card.error {
    border-color: #f87171;
  }

  .row {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .row span {
    color: #475569;
  }

  button {
    align-self: flex-start;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: 1px solid #cbd5e1;
    background: #ffffff;
    cursor: pointer;
    font: inherit;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f1f5f9;
      background-color: #0f172a;
    }

    .subtitle,
    .row span {
      color: #94a3b8;
    }

    .card {
      background: #1e293b;
      border-color: #334155;
    }

    button {
      background: #0f172a;
      color: #f1f5f9;
      border-color: #475569;
    }
  }
</style>
