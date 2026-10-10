// Exercise the production resize handler with a deliberately slow bridge.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../Interface/static/js/main.js'), 'utf8');
const code = source.slice(source.indexOf('    let resizeGestureActive = false;'), source.indexOf('    const updateProtectionLights'));
const tick = () => new Promise(resolve => setImmediate(resolve));
function target() {
    const listeners = new Map();
    return {
        addEventListener: (name, cb) => listeners.set(name, cb),
        removeEventListener: (name, cb) => { if (listeners.get(name) === cb) listeners.delete(name); },
        fire: (name, args = {}) => listeners.get(name)?.({ type: name, ...args }),
        listeners,
    };
}
function fixture() {
    const handle = { ...target(), dataset: { dir: 'se' } };
    const document = target(), window = target();
    const classes = new Set();
    document.body = { classList: { add: x => classes.add(x), remove: x => classes.delete(x) } };
    document.querySelectorAll = () => [handle];
    let start, frames = new Map(), serial = 0;
    const calls = [], resolves = [];
    window.pywebview = { api: {
        begin_window_resize: () => new Promise(resolve => { start = resolve; }),
        update_window_resize: (...args) => { calls.push(['update', ...args]); return new Promise(resolve => resolves.push(resolve)); },
        end_window_resize: async token => { calls.push(['end', token]); return true; },
    } };
    vm.runInNewContext(code, { document, window, console,
        requestAnimationFrame: cb => { frames.set(++serial, cb); return serial; },
        cancelAnimationFrame: id => frames.delete(id),
    });
    handle.fire('mousedown', { button: 0, screenX: 100, screenY: 100, preventDefault() {}, stopPropagation() {} });
    return { document, window, classes, calls, resolves, start: () => start('token'),
        frame: () => { const batch = [...frames.values()]; frames.clear(); batch.forEach(cb => cb()); } };
}
(async () => {
    const early = fixture();
    early.document.fire('mouseup', { screenX: 102, screenY: 103 });
    early.start(); await tick();
    assert.deepEqual(early.calls, [['update', 2, 3, 'token']]);
    early.resolves.shift()(true); await tick();
    assert.deepEqual(early.calls.at(-1), ['end', 'token']);
    assert.equal(early.document.listeners.size, 0);
    assert.equal(early.classes.size, 0);

    const slow = fixture(); slow.start(); await tick();
    slow.document.fire('mousemove', { screenX: 110, screenY: 110, buttons: 1 }); slow.frame();
    for (let n = 11; n < 80; n++) {
        slow.document.fire('mousemove', { screenX: 100 + n, screenY: 100 + n, buttons: 1 }); slow.frame();
    }
    slow.document.fire('mouseup', { screenX: 180, screenY: 180 });
    assert.equal(slow.calls.length, 1, 'one bridge update at a time');
    slow.resolves.shift()(true); await tick(); slow.frame();
    assert.deepEqual(slow.calls[1], ['update', 80, 80, 'token']);
    slow.resolves.shift()(true); await tick();
    assert.deepEqual(slow.calls[2], ['end', 'token']);
    assert.equal(slow.classes.size, 0);

    const blur = fixture(); blur.start(); await tick(); blur.window.fire('blur'); await tick();
    assert.deepEqual(blur.calls, [['end', 'token']]);
    assert.equal(blur.document.listeners.size, 0);
    console.log('Window resize: PASS (early release, latest position, serialized bridge, end ordering, blur cleanup)');
})().catch(error => { console.error(error); process.exitCode = 1; });
