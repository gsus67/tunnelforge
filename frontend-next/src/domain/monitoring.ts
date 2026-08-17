export interface MonitoringTarget {
  servidor: string;
  localPort: number;
  remotePort: number;
  peerWireGuard: boolean;
}

export interface WireGuardPeerLive {
  nombre: string;
  servidor: string;
  interfaz: string;
  allowedIps: string;
  key: string;
  rxMbit: number;
  txMbit: number;
  handshakeAge: number;
}

export interface MonitoringProgress {
  operacion: string;
  etapa: string;
  porcentaje: number;
  activo: boolean;
  mostrar: boolean;
  log: string[];
}
