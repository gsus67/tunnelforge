import type { MonitoringProgress, WireGuardPeerLive } from "../domain/monitoring";

// Contrato que posteriormente será implementado por bindings generados por Wails.
export interface MonitoringService {
  getProgress(): Promise<MonitoringProgress>;
  getWireGuardPeers(): Promise<WireGuardPeerLive[]>;
  prepareMonitor(): Promise<void>;
  applyTargets(serverNames: string[]): Promise<void>;
}
