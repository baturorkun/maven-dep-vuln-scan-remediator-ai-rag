#!/usr/bin/env python3
"""
OWASP Dependency Check Scanner
Clean, modular version for scanning Maven projects
"""

import argparse
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from remediation import RemediationGenerator


class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(message: str):
    """Print colored header"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{message}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.RESET}\n")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {message}{Colors.RESET}", file=sys.stderr)


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ {message}{Colors.RESET}")


def find_all_pom_files(directory: str) -> List[Path]:
    """
    Find all pom.xml files in directory recursively

    Args:
        directory: Root directory to search

    Returns:
        List of Path objects pointing to pom.xml files
    """
    pom_files = []
    for root, dirs, files in os.walk(directory):
        if 'pom.xml' in files:
            pom_files.append(Path(root) / 'pom.xml')
    return pom_files


def load_plugin_xml(plugin_xml_path: str) -> Optional[ET.Element]:
    """
    Load plugin configuration from XML file

    Args:
        plugin_xml_path: Path to plugin XML file

    Returns:
        Plugin XML element or None if error
    """
    try:
        tree = ET.parse(plugin_xml_path)
        plugin = tree.getroot()

        if plugin.tag != 'plugin':
            print_error(f"Plugin XML root element must be <plugin>, found <{plugin.tag}>")
            return None

        return plugin
    except FileNotFoundError:
        print_error(f"Plugin XML file not found: {plugin_xml_path}")
        return None
    except ET.ParseError as e:
        print_error(f"Failed to parse plugin XML: {e}")
        return None


def register_namespace_prefixes(root: ET.Element):
    """Register common Maven namespaces to avoid ns0, ns1 prefixes"""
    # Get the namespace from the root element
    if root.tag.startswith('{'):
        namespace = root.tag[1:root.tag.index('}')]
        ET.register_namespace('', namespace)


def remove_existing_odc_plugin(plugins_element: ET.Element) -> bool:
    """
    Remove existing OWASP Dependency Check plugin if present

    Args:
        plugins_element: The <plugins> XML element

    Returns:
        True if plugin was removed, False otherwise
    """
    namespace = ''
    if plugins_element.tag.startswith('{'):
        namespace = plugins_element.tag[:plugins_element.tag.index('}')+1]

    removed = False
    for plugin in list(plugins_element.findall(f'{namespace}plugin')):
        group_id = plugin.find(f'{namespace}groupId')
        artifact_id = plugin.find(f'{namespace}artifactId')

        if (group_id is not None and group_id.text == 'org.owasp' and
            artifact_id is not None and artifact_id.text == 'dependency-check-maven'):
            plugins_element.remove(plugin)
            removed = True

    return removed


def inject_plugin_to_pom(pom_path: Path, plugin_element: ET.Element) -> bool:
    """
    Inject OWASP plugin into pom.xml

    Args:
        pom_path: Path to pom.xml
        plugin_element: Plugin XML element to inject

    Returns:
        True if successful, False otherwise
    """
    try:
        # Parse POM
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Register namespace to avoid ns0 prefixes
        register_namespace_prefixes(root)

        # Get namespace
        namespace = ''
        if root.tag.startswith('{'):
            namespace = root.tag[:root.tag.index('}')+1]

        # Find or create <build>
        build = root.find(f'{namespace}build')
        if build is None:
            build = ET.SubElement(root, 'build')

        # Find or create <plugins>
        plugins = build.find(f'{namespace}plugins')
        if plugins is None:
            plugins = ET.SubElement(build, 'plugins')

        # Remove existing ODC plugin
        was_removed = remove_existing_odc_plugin(plugins)
        if was_removed:
            print_info(f"Removed existing ODC plugin from {pom_path}")

        # Clone plugin element to avoid namespace issues
        new_plugin = ET.Element('plugin')
        for child in plugin_element:
            # Deep copy the element tree
            new_child = ET.fromstring(ET.tostring(child))
            new_plugin.append(new_child)

        # Add new plugin
        plugins.append(new_plugin)

        # Write back to file
        tree.write(pom_path, encoding='utf-8', xml_declaration=True)

        print_success(f"Injected plugin into {pom_path}")
        return True

    except Exception as e:
        print_error(f"Failed to inject plugin into {pom_path}: {e}")
        return False


def generate_dot_for_pom(pom_path: Path) -> bool:
    """
    Generate DOT dependency tree for a single POM

    DOT format captures all dependencies including "phantom" packages like
    spring-boot-starter-web that don't produce jar files but are declared
    as direct dependencies in pom.xml.

    Args:
        pom_path: Path to pom.xml

    Returns:
        True if successful, False otherwise
    """
    try:
        pom_dir = pom_path.parent
        target_dir = pom_dir / "target"

        # Create target directory if it doesn't exist
        target_dir.mkdir(exist_ok=True)

        output_file = target_dir / "dependency-graph.dot"

        # Build Maven command
        # DOT format includes phantom/BOM packages that GraphML misses
        cmd = [
            'mvn', '-f', str(pom_path),
            'dependency:tree',
            '-DoutputType=dot',
            f'-DoutputFile={output_file}',
            '-DskipTests'
        ]

        print_info(f"Generating DOT for {pom_path}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0 and output_file.exists():
            print_success(f"DOT created: {output_file}")
            return True
        else:
            print_warning(f"Failed to generate DOT for {pom_path}")
            if result.stderr:
                print(f"  Error: {result.stderr[:200]}")
            return False

    except Exception as e:
        print_error(f"DOT generation failed for {pom_path}: {e}")
        return False


def generate_dot_files(pom_files: List[Path]) -> int:
    """
    Generate DOT dependency tree files for multiple POMs

    Args:
        pom_files: List of POM file paths

    Returns:
        Number of successful DOT generations
    """
    print_header("Generating DOT Dependency Trees")
    print_info(f"Processing {len(pom_files)} POM file(s)")

    success_count = 0
    for pom_file in pom_files:
        if generate_dot_for_pom(pom_file):
            success_count += 1

    print_success(f"Generated {success_count}/{len(pom_files)} DOT files")
    return success_count


def run_odc_scan(pom_path: Optional[Path] = None,
                 target_dir: Optional[str] = None,
                 aggregate: bool = False) -> bool:
    """
    Run OWASP Dependency Check scan

    Args:
        pom_path: Path to specific pom.xml (for single POM scan)
        target_dir: Directory to scan (for directory scan)
        aggregate: Whether to run in aggregate mode

    Returns:
        True if scan successful, False otherwise
    """
    try:
        # Build Maven command
        if pom_path:
            # Single POM scan
            cmd = ['mvn', '-f', str(pom_path),
                   'org.owasp:dependency-check-maven:check',
                   '-DskipTests']
            print_info(f"Scanning single POM: {pom_path}")

        elif target_dir:
            # Directory scan
            working_dir = target_dir

            if aggregate:
                cmd = ['mvn',
                       'org.owasp:dependency-check-maven:aggregate',
                       '-DskipTests']
                print_info(f"Scanning directory in AGGREGATE mode: {target_dir}")
            else:
                cmd = ['mvn',
                       'org.owasp:dependency-check-maven:check',
                       '-DskipTests']
                print_info(f"Scanning directory: {target_dir}")

            # Change to target directory for scan
            os.chdir(working_dir)
        else:
            print_error("Either pom_path or target_dir must be provided")
            return False

        # Run Maven command
        print_header("Running OWASP Dependency Check")
        print(f"{Colors.CYAN}Command: {' '.join(cmd)}{Colors.RESET}\n")

        result = subprocess.run(cmd, capture_output=False)

        if result.returncode == 0:
            print_success("OWASP Dependency Check completed successfully")
            return True
        else:
            print_error(f"OWASP Dependency Check failed with exit code {result.returncode}")
            return False

    except subprocess.CalledProcessError as e:
        print_error(f"Maven command failed: {e}")
        return False
    except Exception as e:
        print_error(f"Scan failed: {e}")
        return False


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command line arguments

    Args:
        args: Parsed arguments

    Returns:
        True if valid, False otherwise
    """
    # Check --aggregate can only be used with --target-dir
    if args.aggregate and args.pom:
        print_error("--aggregate can only be used with --target-dir, not with --pom")
        return False

    # New: --aggregate must NOT be used together with --remediation or --transitive
    if args.aggregate and (args.remediation or args.transitive != 0):
        print_error("--aggregate cannot be used with --remediation or --transitive")
        return False

    # Check --transitive can only be used with --remediation
    if args.transitive != 0 and not args.remediation:
        print_error("--transitive can only be used with --remediation")
        return False

    # Check --pom exists if provided
    if args.pom and not os.path.exists(args.pom):
        print_error(f"POM file not found: {args.pom}")
        return False

    # Check --target-dir exists if provided
    if args.target_dir and not os.path.isdir(args.target_dir):
        print_error(f"Target directory not found: {args.target_dir}")
        return False

    # Check --plugin-xml exists ONLY if --inject-plugin is used
    if args.inject_plugin and not os.path.exists(args.plugin_xml):
        print_error(f"Plugin XML file not found: {args.plugin_xml}")
        return False

    return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='OWASP Dependency Check Scanner for Maven projects',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single POM
  %(prog)s --pom /path/to/pom.xml

  # Scan directory
  %(prog)s --target-dir /path/to/project

  # Scan directory in aggregate mode
  %(prog)s --target-dir /path/to/project --aggregate

  # Inject plugin then scan
  %(prog)s --target-dir /path/to/project --inject-plugin

  # Inject custom plugin XML
  %(prog)s --target-dir /path/to/project --inject-plugin --plugin-xml custom.xml

  # Remediation: Basic (generates DOT + remediation.json)
  %(prog)s --target-dir /path/to/project --remediation

  # Remediation: With transitive dependency checking (2 levels deep)
  %(prog)s --target-dir /path/to/project --remediation --transitive 2

  # Remediation: With full transitive checking (all dependencies, up to 10 levels)
  %(prog)s --target-dir /path/to/project --remediation --transitive

  # Full workflow: inject plugin + remediation (with DOT)
  %(prog)s --target-dir /app --inject-plugin --remediation --transitive
        """
    )

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--pom',
                           help='Path to single pom.xml file to scan')
    scan_group.add_argument('--target-dir',
                           help='Target directory to scan (default: /app)',
                           default=None)
    scan_group.add_argument('--aggregate',
                           action='store_true',
                           help='Run in aggregate mode (only with --target-dir)')

    # Plugin injection options
    plugin_group = parser.add_argument_group('Plugin Injection Options')
    plugin_group.add_argument('--inject-plugin',
                             action='store_true',
                             help='Inject OWASP plugin into POM files')
    plugin_group.add_argument('--plugin-xml',
                             default='owasp.plugin.xml',
                             help='Plugin XML file to inject (default: owasp.plugin.xml)')

    # Remediation options (DOT dependency graph is auto-generated with --remediation)
    remediation_group = parser.add_argument_group('Remediation Options')
    remediation_group.add_argument('--remediation',
                                  action='store_true',
                                  help='Generate remediation suggestions (target/remediation.json) and DOT dependency tree (target/dependency-graph.dot). DOT format includes phantom packages like spring-boot-starter-*.')
    remediation_group.add_argument('--transitive', nargs='?', const=-1, type=int, default=0,
                                  metavar='DEPTH',
                                  help='(Requires --remediation) Enable transitive dependency checking when finding safe versions. DEPTH: number of dependency levels to check (default: infinite if flag present, 0 if absent). Use --transitive 2 for 2 levels, --transitive for all levels (up to 10).')

    args = parser.parse_args()

    # If no pom or target-dir specified, use /app as default
    if not args.pom and not args.target_dir:
        args.target_dir = '/app'
        print_info(f"No target specified, using default: {args.target_dir}")

    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)

    print_header("OWASP Dependency Check Scanner")

    # Handle plugin injection
    if args.inject_plugin:
        print_header("Plugin Injection")

        # Load plugin XML
        plugin_element = load_plugin_xml(args.plugin_xml)
        if plugin_element is None:
            sys.exit(1)

        print_success(f"Loaded plugin configuration from {args.plugin_xml}")

        # Find POMs to inject
        if args.pom:
            pom_files = [Path(args.pom)]
        else:
            target = args.target_dir
            print_info(f"Searching for pom.xml files in {target}")
            pom_files = find_all_pom_files(target)
            print_info(f"Found {len(pom_files)} POM files")

        # Inject plugin into each POM
        success_count = 0
        for pom_file in pom_files:
            if inject_plugin_to_pom(pom_file, plugin_element):
                success_count += 1

        print_success(f"Successfully injected plugin into {success_count}/{len(pom_files)} POM files")

    # Generate remediation report if requested
    if args.remediation:
        # Find POMs to process
        if args.pom:
            pom_files = [Path(args.pom)]
        else:
            target = args.target_dir
            print_info(f"Searching for pom.xml files in {target}")
            pom_files = find_all_pom_files(target)
            print_info(f"Found {len(pom_files)} POM files")

        # Always generate DOT files for dependency tree (includes phantom packages)
        print_header("Generating DOT Dependency Trees")
        dot_success = generate_dot_files(pom_files)
        if dot_success == 0:
            print_warning("No DOT files were generated")

        # Generate remediation suggestions
        print_header("Generating Remediation Suggestions")


        # Generate remediation for EACH POM separately
        allow_major_upgrade = os.getenv('ALLOW_MAJOR_UPGRADE', 'false').lower() in ('true', '1', 'yes')
        if allow_major_upgrade:
            print_warning("ALLOW_MAJOR_UPGRADE enabled: Including major version upgrades")

        # Transitive depth: Command-line arg takes precedence over environment variable
        transitive_depth = int(os.getenv('TRANSITIVE_DEPTH', str(args.transitive)))
        if transitive_depth > 0:
            print_info(f"TRANSITIVE_DEPTH={transitive_depth}: Checking transitive dependencies up to {transitive_depth} level(s)")
        elif transitive_depth == -1:
            print_info(f"TRANSITIVE_DEPTH=infinite: Checking all transitive dependencies (up to 10 levels)")

        generator = RemediationGenerator(allow_major_upgrade=allow_major_upgrade, transitive_depth=transitive_depth)
        total_deps = 0
        save_transitive_logs = transitive_depth != 0

        for pom_file in pom_files:
            print_info(f"Processing {pom_file}")

            # Generate report for this POM only (with transitive log saving if enabled)
            report = generator.generate_remediation_report_for_pom(pom_file, save_transitive_logs=save_transitive_logs)

            if not report:
                print_warning(f"  No dependencies found in {pom_file}")
                continue

            # Save to POM's own target directory (like ODC does)
            pom_dir = pom_file.parent
            output_path = pom_dir / "target" / "remediation.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if generator.save_to_json(report, output_path):
                print_success(f"  Saved to {output_path}")
                print_info(f"  Found {len(report)} dependencies with available upgrades")
                total_deps += len(report)
            else:
                print_warning(f"  Failed to save remediation report to {output_path}")

        print_success(f"Total: {total_deps} dependencies processed across {len(pom_files)} POM files")

    # Run scan only if at least one action was NOT performed
    # (i.e., if user didn't specify --inject-plugin or --remediation)
    should_scan = not (args.inject_plugin or args.remediation)

    if should_scan:
        # Run scan
        if args.pom:
            success = run_odc_scan(pom_path=Path(args.pom))
        else:
            success = run_odc_scan(target_dir=args.target_dir, aggregate=args.aggregate)

        # Exit with appropriate code
        sys.exit(0 if success else 1)
    else:
        # Actions completed successfully without scan
        print_success("All requested operations completed successfully")
        sys.exit(0)


if __name__ == '__main__':
    main()
