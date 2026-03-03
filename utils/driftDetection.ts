import { Issue } from './riskScore';

export function compareScans(previousScan: Issue[], currentScan: Issue[]) {
  const prevIds = new Set(previousScan.map(i => i.id));
  const currIds = new Set(currentScan.map(i => i.id));

  const added = currentScan.filter(i => !prevIds.has(i.id));
  const removed = previousScan.filter(i => !currIds.has(i.id));

  return { added, removed };
}
