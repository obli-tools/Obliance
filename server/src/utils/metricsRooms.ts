/**
 * Where a device's metrics go (DEVICE_METRICS_PUSHED): its tenant's room, and
 * the room of the sockets watching that device (DEVICE_METRICS_WATCH,
 * services/deviceMetricsWatch.service.ts). No imports: the metric emitters
 * (device.service, agentHub.service) use it without a service cycle.
 */
export function metricsWatchRoom(deviceId: number): string {
  return `devicemetrics:${deviceId}`;
}

export function metricsRooms(tenantId: number, deviceId: number): [string, string] {
  return [`tenant:${tenantId}`, metricsWatchRoom(deviceId)];
}
