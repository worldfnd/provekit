"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderProgressBar = void 0;
const nanocolors_1 = require("nanocolors");
const PROGRESS_BLOCKS = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
const PROGRESS_WIDTH = 30;
function createProgressBlocks(value, total) {
    if (value >= total) {
        return PROGRESS_BLOCKS[8].repeat(PROGRESS_WIDTH);
    }
    const count = (PROGRESS_WIDTH * value) / total;
    const floored = Math.floor(count);
    const partialBlock = PROGRESS_BLOCKS[Math.floor((count - floored) * (PROGRESS_BLOCKS.length - 1))];
    return `${PROGRESS_BLOCKS[8].repeat(floored)}${partialBlock}${' '.repeat(PROGRESS_WIDTH - floored - 1)}`;
}
function renderProgressBar(finished, active, total) {
    const progressBlocks = createProgressBlocks(finished + active, total);
    const finishedBlockCount = Math.floor((PROGRESS_WIDTH * finished) / total);
    const finishedBlocks = (0, nanocolors_1.white)(progressBlocks.slice(0, finishedBlockCount));
    const scheduledBlocks = (0, nanocolors_1.gray)(progressBlocks.slice(finishedBlockCount));
    return `|${finishedBlocks}${scheduledBlocks}|`;
}
exports.renderProgressBar = renderProgressBar;
//# sourceMappingURL=renderProgressBar.js.map