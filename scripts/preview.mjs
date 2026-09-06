import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { bootstrap, loadConfiguration } from '../src/bootstrap.mjs';
import { Fabric } from '../src/fabric.mjs';
import { createServer } from '../src/server.mjs';

const directory = resolve('.hoplite/local/preview');
if (!existsSync(join(directory, 'config.json'))) bootstrap(directory);
const fabric = new Fabric(loadConfiguration(directory), directory);
const previewHostSuffixes = (process.env.RAILS_DEVELOPMENT_HOSTS ?? '').split(',').filter(s => s === '.preview.usehoplite.com' || s === '.w.modal.host');
const app = createServer(fabric, { port: 3000, previewHostSuffixes });
await app.listen();
console.log('Synthetic engineering preview on port 3000. Local credentials remain in the ignored private preview directory.');
let closing = false;
async function close() { if (closing) return; closing = true; await app.close(); fabric.close(); }
process.on('SIGINT', close); process.on('SIGTERM', close);
