import { Finding, FindingCategory, PatternResult, PatternScanner, RiskLevel } from '../../shared/types';
import { DANGEROUS_COMMANDS } from '../../shared/constants';

/**
 * VSCode tasks.json structure
 */
interface VSCodeTask {
  label?: string;
  type?: string;
  command?: string;
  args?: string[];
  runOptions?: {
    runOn?: string;
  };
  [key: string]: unknown;
}

interface VSCodeTasksConfig {
  version?: string;
  tasks?: VSCodeTask[];
  [key: string]: unknown;
}

/**
 * Scanner for VSCode tasks.json files
 * Detects auto-execution and dangerous shell commands
 */
export class VSCodeScanner implements PatternScanner {
  /**
   * Check if this scanner applies to the given file path
   */
  appliesTo(filePath: string): boolean {
    return filePath.endsWith('.vscode/tasks.json') || filePath === 'tasks.json';
  }

  /**
   * Scan VSCode tasks.json content for malicious patterns
   */
  scan(content: string, filePath: string): PatternResult {
    const findings: Finding[] = [];

    // Try to parse JSON
    let config: VSCodeTasksConfig;
    try {
      config = JSON.parse(content);
    } catch (error) {
      // Invalid JSON - return a warning
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Invalid JSON in tasks.json - could indicate obfuscation or corruption',
        category: FindingCategory.PARSE_ERROR,
      });
      return { findings };
    }

    // Check if tasks array exists and is valid
    if (!config.tasks || !Array.isArray(config.tasks)) {
      // No tasks defined - safe
      return { findings };
    }

    // Empty tasks array - safe
    if (config.tasks.length === 0) {
      return { findings };
    }

    // Scan each task
    for (let i = 0; i < config.tasks.length; i++) {
      const task = config.tasks[i];
      const taskLabel = task.label || `Task #${i + 1}`;

      // Check for runOn: folderOpen (RED - auto-execute on folder open)
      if (task.runOptions?.runOn === 'folderOpen') {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          description: `Task "${taskLabel}" has runOn: folderOpen - will execute automatically when folder is opened`,
          category: FindingCategory.VSCODE,
          matchedContent: 'runOn: folderOpen',
        });
      }

      // Check for shell type tasks with dangerous commands
      if (task.type === 'shell' || task.type === 'process') {
        const commandStr = this.getFullCommand(task);
        const dangerousCmd = this.findDangerousCommand(commandStr);

        if (dangerousCmd) {
          // If it also has runOn: folderOpen, it's already flagged as RED
          const hasAutoRun = task.runOptions?.runOn === 'folderOpen';

          if (!hasAutoRun) {
            findings.push({
              riskLevel: RiskLevel.YELLOW,
              filePath,
              description: `Task "${taskLabel}" contains potentially dangerous command: ${dangerousCmd}`,
              category: FindingCategory.VSCODE,
              matchedContent: commandStr.substring(0, 100),
            });
          }
        }

        // Check for network calls in commands
        if (this.hasNetworkCall(commandStr)) {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            description: `Task "${taskLabel}" makes network requests`,
            category: FindingCategory.VSCODE,
            matchedContent: commandStr.substring(0, 100),
          });
        }
      }
    }

    return { findings };
  }

  /**
   * Get the full command string from a task
   */
  private getFullCommand(task: VSCodeTask): string {
    let command = task.command || '';

    if (task.args && Array.isArray(task.args)) {
      command += ' ' + task.args.join(' ');
    }

    return command.toLowerCase();
  }

  /**
   * Check if command contains dangerous shell commands
   */
  private findDangerousCommand(command: string): string | null {
    const lowerCommand = command.toLowerCase();

    for (const dangerous of DANGEROUS_COMMANDS) {
      // Check for the command with word boundaries
      const pattern = new RegExp(`\\b${dangerous.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      if (pattern.test(lowerCommand)) {
        return dangerous;
      }
    }

    return null;
  }

  /**
   * Check if command contains network calls
   */
  private hasNetworkCall(command: string): boolean {
    const networkPatterns = [
      /https?:\/\/[^\s"']+/i,
      /\bfetch\b/i,
      /\baxios\b/i,
      /\brequest\b/i,
    ];

    return networkPatterns.some(pattern => pattern.test(command));
  }
}

/**
 * Scan VSCode tasks.json content
 */
export function scanVSCodeTasks(content: string, filePath: string = '.vscode/tasks.json'): PatternResult {
  const scanner = new VSCodeScanner();
  return scanner.scan(content, filePath);
}
