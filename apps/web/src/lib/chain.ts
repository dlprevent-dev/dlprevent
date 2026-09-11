import type { Alert } from './types';
import { fmtBytes } from './api';

/** One link of the chain, from the protected folder to the destination.
 *  `edge` is the label on the arrow leading into this node. */
export interface ChainNode {
  role: 'source' | 'reader' | 'copy' | 'sender' | 'destination';
  label: string;
  sub?: string;
  edge?: string;
}

/** The two shapes the correlator produces in `via` (`correlate.rs`,
 *  `read by {r}, via copy {c}`). Everything else in that field is a sentence
 *  for humans — such as "14 files copied out of the protected folder …" — and
 *  is not taken apart: better no node than a wrong one. */
const READ_BY = /^read by (.+?) \(PID (\d+)\)/;
const VIA_COPY = /via copy (.+)$/;
/** Tacked on the end for link-local destinations; not part of the path. */
const LINK_LOCAL = /,\s*link-local peer.*$/;

/** Prefixes the server puts in front of the destination when storing it
 *  (`db.rs`, `upsert_endpoint_alert`). Without a prefix it is `ip:port`. */
const TARGETS: [string, string][] = [
  ['volume ', 'external volume'],
  ['copy to ', 'copy target'],
  ['upload to ', 'upload'],
];

interface Detail {
  pid?: number;
  via?: string;
  sender_read_directly?: boolean;
}

/** The chain of an alert, as nodes from source to destination.
 *
 *  Built from what the alert carries anyway: files, `via`, process and
 *  destination. The agent does not send a family tree along — more than the
 *  one intermediate step named by `via` cannot be got out of it.
 *
 *  Empty for everything without a process chain: the file server's access
 *  alerts tally who read how much and know no sender.
 */
export function chainOf(a: Alert): ChainNode[] {
  if (a.kind !== 'endpoint' || !a.process) return [];
  const d = (a.detail ?? {}) as Detail;
  const via = (d.via ?? '').replace(LINK_LOCAL, '');
  const out: ChainNode[] = [];

  const source = a.files[0] ?? a.path;
  if (source) {
    out.push({ role: 'source', label: source, sub: a.file_count > 1 ? `+ ${a.file_count - 1} more` : undefined });
  }

  const read = READ_BY.exec(via);
  // Only a *different* process is an intermediate step. One that did the
  // reading itself already stands there as the sender and needs no second
  // node.
  if (read && read[1] !== a.process) {
    out.push({ role: 'reader', label: read[1], sub: `PID ${read[2]}`, edge: 'read by' });
  }
  const copy = VIA_COPY.exec(via);
  if (copy) out.push({ role: 'copy', label: copy[1], edge: 'copied to' });

  out.push({
    role: 'sender',
    label: a.process,
    sub: d.pid ? `PID ${d.pid}` : undefined,
    // How the taint reached the sender is thus in the chain instead of only
    // in the reason text.
    edge: d.sender_read_directly ? 'read directly' : 'taint inherited',
  });

  if (a.remote) {
    const hit = TARGETS.find(([p]) => a.remote!.startsWith(p));
    out.push({
      role: 'destination',
      label: hit ? a.remote.slice(hit[0].length) : a.remote,
      sub: hit?.[1],
      edge: a.bytes > 0 ? `${fmtBytes(a.bytes)} out` : undefined,
    });
  }
  return out;
}
