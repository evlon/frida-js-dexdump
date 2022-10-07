#!/usr/bin/env node
import { main } from './index.js';
!async function () {
    try {
        process.exitCode = await main();
    }
    catch (e) {
        console.error(e);
        process.exitCode = 1;
    }
}();
//# sourceMappingURL=cli.js.map