# Contributing

Thank you for your interest in contributing to this project! We welcome contributions from everyone.

## Getting Started

### Prerequisites

- Rust 1.70.0 or later
- Git

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/gbrigandi/wazuh-client-rs.git
   cd wazuh-client-rs
   ```
3. Build the project:
   ```bash
   cargo build
   ```
4. Run tests:
   ```bash
   cargo test
   ```

## How to Contribute

### Reporting Issues

- Use the issue tracker to report bugs or request features
- Provide clear descriptions and reproduction steps
- Include relevant system information

### Code Contributions

1. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write clean, readable code
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```

4. **Commit your changes**:
   - Use clear, descriptive commit messages
   - Follow conventional commit format when possible

5. **Submit a pull request**:
   - Provide a clear description of your changes
   - Reference any related issues
   - Be responsive to feedback

## Code Style

- Use `cargo fmt` to format your code
- Use `cargo clippy` to catch common mistakes
- Follow Rust naming conventions
- Write documentation for public APIs
- Include examples in documentation when helpful

## Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting
- Add integration tests when appropriate

## Documentation

- Update README.md for new features
- Write clear API documentation
- Add examples to help users understand usage

## Pull Request Guidelines

- Keep changes focused and atomic
- Write clear pull request descriptions
- Be responsive to review feedback
- Ensure CI passes before requesting review

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors

## Questions?

If you have questions about contributing, feel free to:
- Open an issue for discussion
- Reach out to maintainers
- Check existing documentation

Thank you for contributing!

