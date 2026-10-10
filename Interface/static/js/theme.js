'use strict';
(() => {
const themes = {
        "white_switch": { "--bg-window": "245, 245, 247", "--bg-nav": "255, 255, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,0,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--text-on-accent": "255, 255, 255", "--border-color":"210, 210, 215", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" },
        "black_switch": { "--bg-window": "0, 0, 0", "--bg-nav": "28, 28, 30", "--bg-panel": "28, 28, 30", "--bg-hover": "rgba(255,255,255,0.1)", "--text-primary": "216, 216, 220", "--text-secondary": "134, 134, 139", "--text-on-accent": "216, 216, 220", "--border-color":"44, 44, 46", "--accent-color":"10, 132, 255", "--accent-alpha":"rgba(10, 132, 255, 0.1)", "--accent-shadow":"rgba(10, 132, 255, 0.2)", "--accent-hover":"rgba(10, 132, 255, 0.3)" },
        "red_switch": { "--bg-window": "253, 246, 246", "--bg-nav": "255, 240, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,59,48,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--text-on-accent": "255, 255, 255", "--border-color":"250, 220, 220", "--accent-color":"255, 59, 48", "--accent-alpha":"rgba(255, 59, 48, 0.1)", "--accent-shadow":"rgba(255, 59, 48, 0.2)", "--accent-hover":"rgba(255, 59, 48, 0.3)" },
        "yellow_switch": { "--bg-window": "254, 251, 243", "--bg-nav": "255, 248, 230", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,149,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--text-on-accent": "255, 255, 255", "--border-color":"250, 240, 215", "--accent-color":"255, 149, 0", "--accent-alpha":"rgba(255, 149, 0, 0.1)", "--accent-shadow":"rgba(255, 149, 0, 0.2)", "--accent-hover":"rgba(255, 149, 0, 0.3)" },
        "green_switch": { "--bg-window": "246, 253, 248", "--bg-nav": "235, 250, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(52,199,89,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--text-on-accent": "255, 255, 255", "--border-color":"220, 240, 225", "--accent-color":"52, 199, 89", "--accent-alpha":"rgba(52, 199, 89, 0.1)", "--accent-shadow":"rgba(52, 199, 89, 0.2)", "--accent-hover":"rgba(52, 199, 89, 0.3)" },
        "blue_switch": { "--bg-window": "246, 249, 253", "--bg-nav": "235, 244, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,122,255,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--text-on-accent": "255, 255, 255", "--border-color":"220, 230, 250", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" }
    };
const apply = (theme) => {
 const actual = theme === 'system_switch' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'black_switch' : 'white_switch') : theme;
 const vars = themes[actual] || themes.white_switch;
 for (const [key, value] of Object.entries(vars)) document.documentElement.style.setProperty(key, value.startsWith('rgba') ? value : `rgb(${value})`);
};
window.PyasTheme = { themes, apply };
})();
