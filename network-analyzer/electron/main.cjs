const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonProcess;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 1000,
        backgroundColor: '#0b132b',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false, // For simple prototype
        },
        autoHideMenuBar: true,
    });

    // Load Vite dev server or build
    if (process.env.NODE_ENV === 'development') {
        mainWindow.loadURL('http://localhost:5173');
        mainWindow.webContents.openDevTools();
    } else {
        mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
    }

    mainWindow.on('closed', function () {
        mainWindow = null;
    });
}

function startPythonBackend() {
    if (process.env.SKIP_PY_BACKEND === 'true') {
        console.log('Skipping Python backend start (managed externally)');
        return;
    }
    // Assume server.py is in the parent directory for this setup
    // In production, you'd bundle it.
    const scriptPath = path.join(__dirname, '../../server.py');
    console.log(`Starting Python backend from: ${scriptPath}`);

    pythonProcess = spawn('python3', [scriptPath]);

    pythonProcess.stdout.on('data', (data) => {
        console.log(`Python: ${data}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Python Error: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
    });
}

app.on('ready', () => {
    startPythonBackend();
    createWindow();
});

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', function () {
    if (mainWindow === null) createWindow();
});

app.on('will-quit', () => {
    if (pythonProcess) {
        pythonProcess.kill();
    }
});
