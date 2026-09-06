import { Fabric } from '../src/fabric.mjs';

const input = JSON.parse(process.env.IF_COMPOSITION_CRASH_INPUT);
const fabric = new Fabric(input.config, input.directory, () => input.now);
const reserve = fabric.reserveBatch.bind(fabric);
fabric.reserveBatch = (...args) => {
  reserve(...args);
  process.kill(process.pid, 'SIGKILL');
};
fabric.compositions.execute(input.principal, input.execution);
