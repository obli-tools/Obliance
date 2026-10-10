import apiClient from './client';

// Bulk rename ("name replacer") — server: routes/bulkRename.routes.ts.
// Renames only the Obliance alias (display name), never the machine hostname.

export type BulkRenameDelimiter = ',' | ';';

export type BulkRenameRowStatus =
  | 'ok' | 'unchanged' | 'not_found' | 'ambiguous' | 'invalid_name' | 'duplicate' | 'missing_key';

export type BulkRenameWarning = 'duplicate_new_name' | 'name_in_use';

export interface BulkRenamePreviewRow {
  line: number;
  status: BulkRenameRowStatus;
  warnings: BulkRenameWarning[];
  input: { uuid: string | null; oldName: string | null; newName: string };
  matchedBy: 'uuid' | 'name' | 'hostname' | null;
  deviceId: number | null;
  uuid: string | null;
  hostname: string | null;
  currentName: string | null;
  newName: string | null;
  invalidReason: 'not_string' | 'empty' | 'too_long' | 'forbidden_chars' | null;
  candidates: number | null;
}

export interface BulkRenamePreview {
  token: string;
  expiresAt: string;
  targetTenantId: number;
  delimiter: ',' | ';' | '\t';
  headerDetected: boolean;
  rows: BulkRenamePreviewRow[];
  counts: Record<BulkRenameRowStatus | 'total' | 'empty' | 'warnings', number>;
}

export const bulkRenameApi = {
  async exportCsv(targetTenantId: number, delimiter: BulkRenameDelimiter): Promise<{ blob: Blob; filename: string }> {
    const res = await apiClient.get('/bulk-rename/export', {
      params: { targetTenantId, delimiter: delimiter === ';' ? 'semicolon' : 'comma' },
      responseType: 'blob',
    });
    const cd = res.headers['content-disposition'] || res.headers['Content-Disposition'] || '';
    const match = /filename="([^"]+)"/.exec(cd);
    return { blob: res.data as Blob, filename: match ? match[1] : 'obliance-devices-rename.csv' };
  },

  async preview(targetTenantId: number, csv: string): Promise<BulkRenamePreview> {
    const res = await apiClient.post('/bulk-rename/preview', csv, {
      params: { targetTenantId },
      headers: { 'Content-Type': 'text/csv' },
      // Send the text as-is (no JSON serialisation).
      transformRequest: [(data: string) => data],
    });
    return res.data.data as BulkRenamePreview;
  },

  async apply(token: string, lines: number[]): Promise<{ batchId: string; renamed: number; unchanged: number }> {
    const res = await apiClient.post('/bulk-rename/apply', { token, lines });
    return res.data.data;
  },
};
