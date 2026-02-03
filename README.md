# SafeClone

A Chrome Extension that scans GitHub repositories for malicious configurations and supply chain attack patterns before you clone them.

## The Problem

Supply chain attacks are increasingly targeting developers through:
- Malicious VSCode tasks that auto-execute on folder open
- NPM packages with dangerous `postinstall` scripts
- Python packages with code execution in `setup.py`
- Compromised GitHub Actions workflows
- Obfuscated payloads hidden with homoglyphs or high-entropy strings

**SafeClone** helps you identify these threats before they reach your machine.

## Disclaimer

**SafeClone is provided "as is" without warranty of any kind.** This tool is intended as a quick preliminary check and does NOT guarantee the safety of any repository.

- **No 100% guarantee**: SafeClone uses heuristic pattern matching and cannot detect all possible attack vectors, especially novel or sophisticated attacks
- **Not a replacement for manual review**: Developers are still responsible for reviewing code before cloning and executing it
- **No liability**: The authors and contributors are not liable for any damages resulting from the use of this tool or from cloning repositories that were scanned
- **Defense in depth**: Use SafeClone as one layer of your security practices, not your only protection

**Bottom line**: SafeClone helps you catch common threats quickly, but always do your due diligence. If something feels wrong, investigate further before running any code.

## Features

### Risk Classification

SafeClone uses a color-coded risk system:

| Level | Meaning | Examples |
|-------|---------|----------|
| **RED** | Immediate danger - RCE or data exfiltration | `runOn: folderOpen`, `curl \| bash`, secrets in logs |
| **YELLOW** | Suspicious patterns requiring review | Lifecycle hooks, obfuscation, unpinned actions |
| **GREEN** | No common attack vectors found | Safe to clone |

### Detection Capabilities

#### VSCode Tasks (`.vscode/tasks.json`)
- `runOn: folderOpen` - Auto-executes when you open the folder
- Shell tasks with `curl`, `wget`, `bash`, `powershell`
- Network calls in task commands

#### NPM Packages (`package.json`)
- Dangerous commands in `preinstall`, `postinstall`, `prepare` hooks
- Environment variable exfiltration (`process.env`, `$SECRET`)
- `eval()`, `exec()` in lifecycle scripts
- Typosquatting package names
- Suspicious `file:` protocol dependencies

#### Python (`setup.py`, `pyproject.toml`)
- `os.system()`, `subprocess.*()`, `exec()`, `eval()`
- `__import__()` dynamic imports
- Base64 decoding operations
- `cmdclass` overrides
- Sensitive `data_files` targeting `/etc/` or `.ssh`

#### Rust (`Cargo.toml`, `.cargo/config`)
- `rustc-wrapper` or `rustc` overrides (RED)
- `[build-dependencies]` section
- Custom linkers and runners
- Suspicious git dependencies from unknown hosts
- Custom source registries

#### GitHub Actions (`.github/workflows/*.yml`)
- `pull_request_target` with PR checkout (pwn-request vulnerability)
- Command injection via `${{ github.event.* }}`
- Secrets exposure in echo/logs
- `curl | bash` patterns
- Unpinned action versions

#### Obfuscation Detection
- **High Entropy**: Detects base64, encrypted, or obfuscated strings
- **Homoglyphs**: Cyrillic/Greek lookalikes (Trojan Source attacks)
- **Invisible Characters**: Zero-width spaces, BOM, bidi overrides

## Installation

### From Source (Development)

1. Clone the repository:
   ```bash
   git clone https://github.com/AuditWare/safeclone.git
   cd safeclone
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the extension:
   ```bash
   npm run build
   ```

4. Load in Chrome:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `dist/` folder

### Usage

1. Navigate to any public GitHub repository
2. SafeClone automatically scans the repository
3. A shield icon appears showing the risk level:
   - Click to expand and see detailed findings
   - Each finding shows the file, line number, and description

## Limitations

### Public Repositories Only

SafeClone currently only works with **public GitHub repositories**.

**Why?** We initially considered supporting private repos via GitHub Personal Access Tokens, but storing tokens in browser extension storage poses security risks. As a result, we've decided to focus on public repos for now.

**Workaround:** For private repositories or when files cannot be fetched, SafeClone displays a "Scan Incomplete" warning, clearly stating it could not scan the repository. This prevents false negatives where users might think a repo is "safe" when it simply wasn't scanned.

### Rate Limiting

GitHub's public API has rate limits. If you're scanning many repositories quickly, you may hit these limits.

**Workaround:** SafeClone caches scan results to reduce API calls. You can clear the cache from the options page if needed.

### File Size Limits

Very large files may not be fully analyzed to maintain performance.

### Detection Coverage

SafeClone uses heuristic-based detection. It catches common attack patterns but cannot guarantee detection of all malicious code, especially:
- Novel attack vectors
- Heavily obfuscated payloads
- Malicious logic spread across multiple files

**Recommendation:** SafeClone is a first line of defense. Always review code manually before running it, especially from untrusted sources.

## Project Structure

```
safeclone/
├── src/
│   ├── background/          # Service Worker (MV3)
│   │   ├── index.ts         # Entry point
│   │   ├── messageHandler.ts # Chrome runtime messaging
│   │   └── fetchService.ts  # GitHub API interactions
│   │
│   ├── content/             # Content Scripts
│   │   ├── index.ts         # Entry point
│   │   ├── spaNavigationDetector.ts # GitHub SPA navigation
│   │   ├── fileTreeObserver.ts      # File tree monitoring
│   │   └── uiOverlay.ts     # Shadow DOM UI
│   │
│   ├── heuristics/          # Detection Engine
│   │   ├── index.ts         # Scanner orchestrator
│   │   ├── riskClassifier.ts # Risk aggregation
│   │   ├── entropy.ts       # Shannon entropy calculator
│   │   ├── homoglyphDetector.ts # Character analysis
│   │   └── patterns/        # File-specific scanners
│   │       ├── vscode.ts
│   │       ├── npm.ts
│   │       ├── python.ts
│   │       ├── rust.ts
│   │       └── github.ts
│   │
│   ├── shared/              # Shared utilities
│   │   ├── types.ts         # TypeScript interfaces
│   │   ├── constants.ts     # Thresholds & patterns
│   │   ├── messageTypes.ts  # Message definitions
│   │   └── storage.ts       # Chrome storage wrapper
│   │
│   ├── popup/               # Extension popup
│   └── options/             # Settings page
│
├── tests/
│   ├── unit/                # Unit tests
│   └── fixtures/            # Test fixtures
│
└── dist/                    # Build output
```

## Development

### Prerequisites

- Node.js 18+
- npm 9+

### Commands

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Build for production
npm run build

# Build in watch mode (development)
npm run watch
```

### Running Tests

The project has comprehensive unit tests for all heuristic scanners:

```bash
# Run all tests
npm test

# Run specific test file
npm test -- --testPathPattern=vscode

# Run with coverage
npm test -- --coverage
```

### Adding New Detection Patterns

1. Create a new scanner in `src/heuristics/patterns/`:
   ```typescript
   import { PatternResult, Finding, RiskLevel, FindingCategory } from '../../shared/types';

   export function scanMyPattern(content: string, filePath: string): PatternResult {
     const findings: Finding[] = [];

     // Your detection logic here

     return { findings };
   }
   ```

2. Register it in `src/heuristics/index.ts`

3. Add unit tests in `tests/unit/heuristics/`

4. Add test fixtures in `tests/fixtures/`

## Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

- Use GitHub Issues to report bugs
- Include steps to reproduce
- Share example repositories (if public) that trigger false positives/negatives

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add/update tests
5. Ensure all tests pass: `npm test`
6. Submit a pull request

### Areas for Contribution

- **New Detection Patterns**: Help catch more attack vectors
- **False Positive Reduction**: Improve pattern accuracy
- **Performance**: Optimize scanning for large repositories
- **UI/UX**: Improve the results display
- **Documentation**: Improve docs and examples
- **Browser Support**: Port to Firefox/Edge

### Code Style

- TypeScript with strict mode
- Jest for testing
- Follow existing patterns in the codebase

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately via GitHub Security Advisories rather than opening a public issue.

### Design Decisions

- **No token storage**: We intentionally don't support private repos to avoid token theft risks
- **Minimal permissions**: Only requests necessary Chrome permissions
- **Shadow DOM**: UI is isolated to prevent page interference
- **No external services**: All analysis runs locally in your browser

## License

MIT License - see [LICENSE](LICENSE) for details.

This software is provided without warranty. See the [Disclaimer](#disclaimer) section above.

