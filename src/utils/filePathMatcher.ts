import { CRITICAL_FILES, SCAN_TRIGGER_FOLDERS } from '../shared/constants';

/**
 * Check if a file tree contains a specific folder
 */
export function hasFolder(fileTree: string[], folderPath: string): boolean {
  const normalizedFolder = folderPath.endsWith('/') ? folderPath : `${folderPath}/`;

  return fileTree.some(
    file => file === folderPath || file.startsWith(normalizedFolder) || file === normalizedFolder.slice(0, -1)
  );
}

/**
 * Check if a file tree contains a specific file
 */
export function hasFile(fileTree: string[], filePath: string): boolean {
  return fileTree.includes(filePath);
}

/**
 * Determine which files need to be scanned based on the file tree
 */
export function getFilesToScan(fileTree: string[]): string[] {
  const filesToScan: string[] = [];

  // VSCode - only if .vscode folder exists
  if (hasFolder(fileTree, '.vscode')) {
    if (hasFile(fileTree, CRITICAL_FILES.VSCODE.TASKS) || hasFolder(fileTree, '.vscode')) {
      filesToScan.push(CRITICAL_FILES.VSCODE.TASKS);
    }
  }

  // NPM - if package.json exists
  if (hasFile(fileTree, CRITICAL_FILES.NPM.PACKAGE)) {
    filesToScan.push(CRITICAL_FILES.NPM.PACKAGE);
  }

  // Python - check for setup.py or pyproject.toml
  if (hasFile(fileTree, CRITICAL_FILES.PYTHON.SETUP)) {
    filesToScan.push(CRITICAL_FILES.PYTHON.SETUP);
  }
  if (hasFile(fileTree, CRITICAL_FILES.PYTHON.PYPROJECT)) {
    filesToScan.push(CRITICAL_FILES.PYTHON.PYPROJECT);
  }

  // Rust - if Cargo.toml exists
  if (hasFile(fileTree, CRITICAL_FILES.RUST.CARGO)) {
    filesToScan.push(CRITICAL_FILES.RUST.CARGO);
  }

  // Rust .cargo config - check both variants
  if (hasFolder(fileTree, '.cargo')) {
    filesToScan.push(CRITICAL_FILES.RUST.CARGO_CONFIG);
    filesToScan.push(CRITICAL_FILES.RUST.CARGO_CONFIG_ALT);
  }

  // GitHub Actions - if .github/workflows exists
  if (hasFolder(fileTree, '.github/workflows')) {
    const workflowFiles = fileTree.filter(
      file =>
        file.startsWith('.github/workflows/') &&
        (file.endsWith('.yml') || file.endsWith('.yaml'))
    );
    filesToScan.push(...workflowFiles);
  }

  return filesToScan;
}

/**
 * Get file scanner type based on file path
 */
export function getScannerType(
  filePath: string
): 'vscode' | 'npm' | 'python' | 'rust' | 'github' | null {
  if (filePath.includes('.vscode/') && filePath.endsWith('tasks.json')) {
    return 'vscode';
  }

  if (filePath.endsWith('package.json')) {
    return 'npm';
  }

  if (filePath.endsWith('setup.py') || filePath.endsWith('pyproject.toml')) {
    return 'python';
  }

  if (filePath.endsWith('Cargo.toml') || filePath.includes('.cargo/config')) {
    return 'rust';
  }

  if (filePath.includes('.github/workflows/') && (filePath.endsWith('.yml') || filePath.endsWith('.yaml'))) {
    return 'github';
  }

  return null;
}

/**
 * Check if a file path is a critical file
 */
export function isCriticalFile(filePath: string): boolean {
  return getScannerType(filePath) !== null;
}

/**
 * Extract workflow file names from a file tree
 */
export function getWorkflowFiles(fileTree: string[]): string[] {
  return fileTree.filter(
    file =>
      file.startsWith('.github/workflows/') &&
      (file.endsWith('.yml') || file.endsWith('.yaml'))
  );
}

/**
 * Check if scanning is needed for this repository
 */
export function needsScanning(fileTree: string[]): boolean {
  // Check for any scan trigger folders or critical files
  const hasTriggerFolder = Object.values(SCAN_TRIGGER_FOLDERS).some(folder =>
    hasFolder(fileTree, folder)
  );

  const hasCriticalFile =
    hasFile(fileTree, CRITICAL_FILES.NPM.PACKAGE) ||
    hasFile(fileTree, CRITICAL_FILES.PYTHON.SETUP) ||
    hasFile(fileTree, CRITICAL_FILES.PYTHON.PYPROJECT) ||
    hasFile(fileTree, CRITICAL_FILES.RUST.CARGO);

  return hasTriggerFolder || hasCriticalFile;
}
